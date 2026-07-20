package com.github.unidbg.trace;

import capstone.api.Instruction;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.WriteHook;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class NormalizedTraceInstaller {

    private NormalizedTraceInstaller() {
    }

    public static NormalizedTraceSession install(Emulator<?> emulator, NormalizedTraceConfig config) throws IOException {
        NormalizedTraceConfig actualConfig = config == null ? NormalizedTraceConfig.builder().build() : config;
        NormalizedTraceWriter writer = new NormalizedTraceWriter(actualConfig);
        NormalizedTraceSession session = new NormalizedTraceSession(emulator, actualConfig, writer);
        if (actualConfig.level == NormalizedTraceConfig.Level.OFF) {
            return session;
        }
        if (actualConfig.includesInstruction()) {
            TraceCodeHook hook = new TraceCodeHook(session);
            emulator.getBackend().hook_add_new(hook, actualConfig.traceBegin, actualConfig.traceEnd, null);
        }
        if (actualConfig.includesMemory()) {
            List<AddressRange> ranges = actualConfig.memoryRanges.isEmpty()
                    ? Collections.singletonList(new AddressRange(1, 0))
                    : actualConfig.memoryRanges;
            for (AddressRange range : ranges) {
                emulator.getBackend().hook_add_new(new TraceReadHook(session), range.begin, range.end, null);
                emulator.getBackend().hook_add_new(new TraceWriteHook(session), range.begin, range.end, null);
            }
        }
        return session;
    }

    private static final class TraceCodeHook implements CodeHook {
        private final NormalizedTraceSession session;
        private final NormalizedTraceModuleResolver resolver;
        private UnHook unHook;

        private TraceCodeHook(NormalizedTraceSession session) {
            this.session = session;
            this.resolver = new NormalizedTraceModuleResolver(session.config().targetModule);
        }

        @Override
        public void hook(Backend backend, long address, int size, Object user) {
            NormalizedTraceConfig config = session.config();
            Map<String, String> currentRegisters = config.includesRegisters()
                    ? NormalizedTraceRegisters.snapshot(backend, config.selectedRegisters)
                    : Collections.emptyMap();
            PendingInstruction previous = session.pendingInstruction();
            if (previous != null) {
                previous.flush(session.writer(), currentRegisters);
            }
            session.pendingInstruction(buildPendingInstruction(backend, address, size, currentRegisters));
            session.stopIfNeeded();
        }

        private PendingInstruction buildPendingInstruction(Backend backend, long address, int size, Map<String, String> beforeRegisters) {
            NormalizedTraceConfig config = session.config();
            byte[] bytes = readBytes(backend, address, size);
            Instruction instruction = decodeInstruction(address, bytes);
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("thread_id", "main");
            event.put("kind", "instruction");
            event.put("pc", NormalizedTraceModuleResolver.hex(address));
            resolver.putModuleFields(event, address);
            Map<String, Object> instructionJson = new LinkedHashMap<>();
            instructionJson.put("bytes", config.includeInstructionBytes ? Hex.encodeHexString(bytes) : "");
            instructionJson.put("mnemonic", instruction == null ? "unknown" : safeString(instruction.getMnemonic(), "unknown"));
            instructionJson.put("operands", instruction == null ? Collections.emptyList() : operands(instruction));
            event.put("instruction", instructionJson);
            event.put("memory", Collections.emptyList());
            event.put("branch", branch(address, size, instruction));
            Map<String, Object> backendJson = new LinkedHashMap<>();
            backendJson.put("name", config.backendName);
            backendJson.put("raw_kind", "code_hook");
            event.put("backend", backendJson);
            Map<String, String> reads = config.includeRegisterReads && instruction != null
                    ? NormalizedTraceRegisters.reads(session.emulator(), backend, instruction, beforeRegisters)
                    : Collections.emptyMap();
            return new PendingInstruction(event, beforeRegisters, reads);
        }

        private byte[] readBytes(Backend backend, long address, int size) {
            try {
                return backend.mem_read(address, size);
            } catch (RuntimeException e) {
                session.writer().addDiagnostic("instruction bytes read failed at " + NormalizedTraceModuleResolver.hex(address) + ": " + e.getMessage());
                return new byte[0];
            }
        }

        private Instruction decodeInstruction(long address, byte[] bytes) {
            if (!session.config().includeInstructionDecode || bytes.length == 0) {
                return null;
            }
            try {
                Instruction[] instructions = session.emulator().disassemble(address, bytes, false, 1);
                return instructions.length == 0 ? null : instructions[0];
            } catch (RuntimeException e) {
                session.writer().addDiagnostic("instruction decode failed at " + NormalizedTraceModuleResolver.hex(address) + ": " + e.getMessage());
                return null;
            }
        }

        private List<String> operands(Instruction instruction) {
            String opStr = instruction.getOpStr();
            if (opStr == null || opStr.trim().isEmpty()) {
                return Collections.emptyList();
            }
            String[] parts = opStr.split(",");
            List<String> operands = new ArrayList<>(parts.length);
            for (String part : parts) {
                operands.add(part.trim());
            }
            return operands;
        }

        private Map<String, Object> branch(long address, int size, Instruction instruction) {
            if (instruction == null || instruction.getMnemonic() == null) {
                return null;
            }
            String mnemonic = instruction.getMnemonic().toLowerCase(Locale.ROOT);
            if (!(mnemonic.equals("b") || mnemonic.startsWith("b.") || mnemonic.equals("bl") || mnemonic.equals("blr") || mnemonic.equals("br") || mnemonic.equals("ret") || mnemonic.equals("cbz") || mnemonic.equals("cbnz") || mnemonic.equals("tbz") || mnemonic.equals("tbnz"))) {
                return null;
            }
            Map<String, Object> branch = new LinkedHashMap<>();
            branch.put("taken", true);
            String target = parseBranchTarget(instruction.getOpStr());
            branch.put("target", target == null ? null : target);
            branch.put("fallthrough", NormalizedTraceModuleResolver.hex(address + size));
            branch.put("condition_registers", mnemonic.startsWith("b.") ? Collections.singletonList("nzcv") : Collections.emptyList());
            return branch;
        }

        private String parseBranchTarget(String opStr) {
            if (opStr == null) {
                return null;
            }
            for (String part : opStr.split(",")) {
                String trimmed = part.trim();
                if (trimmed.startsWith("#")) {
                    trimmed = trimmed.substring(1);
                }
                if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                    return trimmed.toLowerCase(Locale.ROOT);
                }
            }
            return null;
        }

        @Override
        public void onAttach(UnHook unHook) {
            this.unHook = unHook;
            session.addHook(unHook);
        }

        @Override
        public void detach() {
            if (unHook != null) {
                unHook.unhook();
                unHook = null;
            }
        }
    }

    private static final class TraceReadHook implements ReadHook {
        private final NormalizedTraceSession session;
        private final NormalizedTraceModuleResolver resolver;
        private UnHook unHook;

        private TraceReadHook(NormalizedTraceSession session) {
            this.session = session;
            this.resolver = new NormalizedTraceModuleResolver(session.config().targetModule);
        }

        @Override
        public void hook(Backend backend, long address, int size, Object user) {
            writeMemoryEvent(backend, "memory_read", "read_hook", "read", address, size, null);
            session.stopIfNeeded();
        }

        private void writeMemoryEvent(Backend backend, String kind, String rawKind, String access, long address, int size, Long writeValue) {
            Map<String, Object> event = baseMemoryEvent(backend, kind, rawKind);
            event.put("memory", Collections.singletonList(memoryAccess(backend, access, address, size, writeValue)));
            session.writer().writeEvent(kind, event);
        }

        private Map<String, Object> baseMemoryEvent(Backend backend, String kind, String rawKind) {
            long pc = readPc(backend);
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("thread_id", "main");
            event.put("kind", kind);
            event.put("pc", NormalizedTraceModuleResolver.hex(pc));
            resolver.putModuleFields(event, pc);
            Map<String, Object> backendJson = new LinkedHashMap<>();
            backendJson.put("name", session.config().backendName);
            backendJson.put("raw_kind", rawKind);
            event.put("backend", backendJson);
            return event;
        }

        private Map<String, Object> memoryAccess(Backend backend, String access, long address, int size, Long writeValue) {
            Map<String, Object> memory = new LinkedHashMap<>();
            memory.put("access", access);
            memory.put("address", NormalizedTraceModuleResolver.hex(address));
            memory.put("size", size);
            memory.put("value_hex", valueHex(backend, access, address, size, writeValue));
            memory.put("region", null);
            memory.put("module", null);
            memory.put("symbol", null);
            memory.put("taint", Collections.emptyList());
            memory.put("note", null);
            return memory;
        }

        private String valueHex(Backend backend, String access, long address, int size, Long writeValue) {
            NormalizedTraceConfig config = session.config();
            if (!config.includeMemoryValues || config.memoryValueLimit <= 0) {
                return null;
            }
            if ("write".equals(access) && writeValue != null) {
                return formatIntegerValue(writeValue, Math.min(size, 8));
            }
            int limit = Math.min(size, config.memoryValueLimit);
            try {
                return Hex.encodeHexString(backend.mem_read(address, limit));
            } catch (RuntimeException e) {
                session.writer().addDiagnostic("memory value read failed at " + NormalizedTraceModuleResolver.hex(address) + ": " + e.getMessage());
                return null;
            }
        }

        @Override
        public void onAttach(UnHook unHook) {
            this.unHook = unHook;
            session.addHook(unHook);
        }

        @Override
        public void detach() {
            if (unHook != null) {
                unHook.unhook();
                unHook = null;
            }
        }
    }

    private static final class TraceWriteHook implements WriteHook {
        private final TraceReadHook delegate;
        private UnHook unHook;

        private TraceWriteHook(NormalizedTraceSession session) {
            this.delegate = new TraceReadHook(session);
        }

        @Override
        public void hook(Backend backend, long address, int size, long value, Object user) {
            delegate.writeMemoryEvent(backend, "memory_write", "write_hook", "write", address, size, value);
            delegate.session.stopIfNeeded();
        }

        @Override
        public void onAttach(UnHook unHook) {
            this.unHook = unHook;
            delegate.session.addHook(unHook);
        }

        @Override
        public void detach() {
            if (unHook != null) {
                unHook.unhook();
                unHook = null;
            }
        }
    }

    private static long readPc(Backend backend) {
        try {
            return backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue();
        } catch (RuntimeException ignored) {
            try {
                return backend.reg_read(unicorn.ArmConst.UC_ARM_REG_PC).longValue();
            } catch (RuntimeException ignoredAgain) {
                return 0;
            }
        }
    }

    private static String safeString(String value, String fallback) {
        return value == null ? fallback : value;
    }

    private static String formatIntegerValue(long value, int size) {
        byte[] bytes = new byte[Math.max(size, 1)];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) ((value >>> (i * 8)) & 0xff);
        }
        return Hex.encodeHexString(bytes);
    }
}
