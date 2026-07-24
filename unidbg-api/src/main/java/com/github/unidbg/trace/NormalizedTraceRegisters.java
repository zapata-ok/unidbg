package com.github.unidbg.trace;

import capstone.api.Instruction;
import capstone.api.RegsAccess;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;

import java.util.LinkedHashMap;
import java.util.Map;

final class NormalizedTraceRegisters {

    private NormalizedTraceRegisters() {
    }

    static Map<String, String> snapshot(Backend backend, Map<String, Integer> registers) {
        LinkedHashMap<String, String> snapshot = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> entry : registers.entrySet()) {
            try {
                Number value = backend.reg_read(entry.getValue());
                snapshot.put(entry.getKey(), NormalizedTraceModuleResolver.hex(value.longValue()));
            } catch (RuntimeException ignored) {
                // Skip registers unsupported by current backend.
            }
        }
        return snapshot;
    }

    static Snapshot snapshot(Backend backend, NormalizedTraceConfig config) {
        long[] values = new long[config.selectedRegisterIds.length];
        boolean[] valid = new boolean[config.selectedRegisterIds.length];
        for (int i = 0; i < config.selectedRegisterIds.length; i++) {
            try {
                values[i] = backend.reg_read(config.selectedRegisterIds[i]).longValue();
                valid[i] = true;
            } catch (RuntimeException ignored) {
                // Skip registers unsupported by current backend.
            }
        }
        return new Snapshot(config.selectedRegisterNames, values, valid);
    }

    static Map<String, String> delta(Map<String, String> before, Map<String, String> after) {
        LinkedHashMap<String, String> writes = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : after.entrySet()) {
            String oldValue = before.get(entry.getKey());
            if (oldValue == null || !oldValue.equals(entry.getValue())) {
                writes.put(entry.getKey(), entry.getValue());
            }
        }
        return writes;
    }

    static Map<String, String> reads(Emulator<?> emulator, Backend backend, Instruction instruction, Map<String, String> snapshot) {
        LinkedHashMap<String, String> reads = new LinkedHashMap<>();
        try {
            RegsAccess access = instruction.regsAccess();
            if (access == null) {
                return reads;
            }
            for (short reg : access.getRegsRead()) {
                String name = canonicalRegisterName(emulator, instruction, reg);
                if (name == null || reads.containsKey(name)) {
                    continue;
                }
                String value = snapshot.get(name);
                if (value != null) {
                    reads.put(name, value);
                } else {
                    int regId = instruction.mapToUnicornReg(reg);
                    value = NormalizedTraceModuleResolver.hex(backend.reg_read(regId).longValue());
                    reads.put(name, value);
                }
            }
        } catch (RuntimeException ignored) {
            // Register reads are best effort.
        }
        return reads;
    }

    static Map<String, String> reads(Emulator<?> emulator, Backend backend, Instruction instruction, Snapshot snapshot) {
        LinkedHashMap<String, String> reads = new LinkedHashMap<>();
        try {
            RegsAccess access = instruction.regsAccess();
            if (access == null) {
                return reads;
            }
            for (short reg : access.getRegsRead()) {
                String name = canonicalRegisterName(emulator, instruction, reg);
                if (name == null || reads.containsKey(name)) {
                    continue;
                }
                Long value = snapshot == null ? null : snapshot.get(name);
                if (value != null) {
                    reads.put(name, NormalizedTraceModuleResolver.hex(value));
                } else {
                    int regId = instruction.mapToUnicornReg(reg);
                    reads.put(name, NormalizedTraceModuleResolver.hex(backend.reg_read(regId).longValue()));
                }
            }
        } catch (RuntimeException ignored) {
            // Register reads are best effort.
        }
        return reads;
    }

    static final class Snapshot {
        final String[] names;
        final long[] values;
        final boolean[] valid;

        Snapshot(String[] names, long[] values, boolean[] valid) {
            this.names = names;
            this.values = values;
            this.valid = valid;
        }

        Long get(String name) {
            for (int i = 0; i < names.length; i++) {
                if (valid[i] && names[i].equals(name)) {
                    return values[i];
                }
            }
            return null;
        }
    }

    private static String canonicalRegisterName(Emulator<?> emulator, Instruction instruction, short capstoneReg) {
        String name = instruction.regName(capstoneReg);
        if (name == null || name.isEmpty()) {
            return null;
        }
        name = name.toLowerCase();
        if (emulator.is64Bit() && name.matches("w\\d+")) {
            return "x" + name.substring(1);
        }
        if ("lr".equals(name) && emulator.is64Bit()) {
            return "x30";
        }
        return name;
    }
}
