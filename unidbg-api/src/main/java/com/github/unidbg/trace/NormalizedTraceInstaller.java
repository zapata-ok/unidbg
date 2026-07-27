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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class NormalizedTraceInstaller {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private NormalizedTraceInstaller() {
    }

    public static NormalizedTraceSession install(Emulator<?> emulator, NormalizedTraceConfig config) throws IOException {
        NormalizedTraceConfig actualConfig = config == null ? NormalizedTraceConfig.builder().build() : config;
        NormalizedTraceWriter writer = new NormalizedTraceWriter(actualConfig);
        NormalizedTraceSession session = new NormalizedTraceSession(emulator, actualConfig, writer);
        if (actualConfig.level == NormalizedTraceConfig.Level.OFF) {
            return session;
        }
        if (actualConfig.level == NormalizedTraceConfig.Level.COUNT_ONLY) {
            CountCodeHook hook = new CountCodeHook(session);
            long begin = actualConfig.targetModule == null && actualConfig.targetModuleName != null ? 1 : actualConfig.traceBegin;
            long end = actualConfig.targetModule == null && actualConfig.targetModuleName != null ? 0 : actualConfig.traceEnd;
            emulator.getBackend().hook_add_new(hook, begin, end, null);
            List<AddressRange> ranges = actualConfig.memoryRanges.isEmpty()
                    ? Collections.singletonList(new AddressRange(1, 0))
                    : actualConfig.memoryRanges;
            CountMemoryHook memoryHook = new CountMemoryHook(session);
            for (AddressRange range : ranges) {
                emulator.getBackend().hook_add_new(memoryHook, range.begin, range.end, null);
                emulator.getBackend().hook_add_new(new CountWriteHook(memoryHook), range.begin, range.end, null);
            }
        } else if (actualConfig.includesInstruction()) {
            TraceCodeHook hook = new TraceCodeHook(session);
            long begin = actualConfig.targetModule == null && actualConfig.targetModuleName != null ? 1 : actualConfig.traceBegin;
            long end = actualConfig.targetModule == null && actualConfig.targetModuleName != null ? 0 : actualConfig.traceEnd;
            emulator.getBackend().hook_add_new(hook, begin, end, null);
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

    private static final class CountCodeHook implements CodeHook {
        private final NormalizedTraceSession session;
        private final NormalizedTraceModuleResolver resolver;
        private final CachedInstruction[] instructionCache = new CachedInstruction[8192];
        private long svcMemoryBase = -1;
        private long svcMemoryEnd = -1;
        private UnHook unHook;
        private NormalizedTraceRegisters.Snapshot previousBeforeRegisters;

        private CountCodeHook(NormalizedTraceSession session) {
            this.session = session;
            this.resolver = new NormalizedTraceModuleResolver(session.emulator(), session.config().targetModule, session.config().targetModuleName);
        }

        @Override
        public void hook(Backend backend, long address, int size, Object user) {
            NormalizedTraceConfig config = session.config();
            if (config.targetModule == null && config.targetModuleName != null && !resolver.contains(address)) {
                countPreviousRegisterWrites(backend);
                session.stopIfNeeded();
                return;
            }
            if (!isSvcMemory(address)) {
                NormalizedTraceRegisters.Snapshot currentRegisters = NormalizedTraceRegisters.snapshot(backend, config);
                countRegisterWrites(previousBeforeRegisters, currentRegisters);
                CachedInstruction instruction = cachedInstruction(backend, address, size);
                if (instruction.branch != null) {
                    session.writer().countBranch();
                }
                session.writer().countInstruction();
                previousBeforeRegisters = currentRegisters;
            }
            session.stopIfNeeded();
        }

        private void countPreviousRegisterWrites(Backend backend) {
            if (previousBeforeRegisters != null) {
                NormalizedTraceRegisters.Snapshot currentRegisters = NormalizedTraceRegisters.snapshot(backend, session.config());
                countRegisterWrites(previousBeforeRegisters, currentRegisters);
                previousBeforeRegisters = null;
            }
        }

        private void countRegisterWrites(NormalizedTraceRegisters.Snapshot before, NormalizedTraceRegisters.Snapshot after) {
            if (before == null || after == null) {
                return;
            }
            int len = Math.min(before.names.length, after.names.length);
            int count = 0;
            for (int i = 0; i < len; i++) {
                if (before.valid[i] && after.valid[i] && before.values[i] != after.values[i]) {
                    count++;
                }
            }
            session.writer().countRegisterWrites(count);
        }

        private CachedInstruction cachedInstruction(Backend backend, long address, int size) {
            int slot = (int) ((address >>> 2) & (instructionCache.length - 1));
            CachedInstruction cached = instructionCache[slot];
            if (cached != null && cached.address == address && cached.size == size) {
                return cached;
            }
            byte[] bytes = readBytes(backend, address, size);
            Instruction rawInstruction = decodeInstruction(address, bytes);
            String mnemonic = rawInstruction == null ? "unknown" : safeString(rawInstruction.getMnemonic(), "unknown");
            CachedInstruction decoded = new CachedInstruction(
                    address,
                    size,
                    "",
                    mnemonic,
                    Collections.<String>emptyList(),
                    branch(address, size, rawInstruction),
                    null);
            instructionCache[slot] = decoded;
            return decoded;
        }

        private byte[] readBytes(Backend backend, long address, int size) {
            try {
                return backend.mem_read(address, size);
            } catch (RuntimeException e) {
                session.writer().addDiagnostic("count-only instruction bytes read failed at " + NormalizedTraceModuleResolver.hex(address) + ": " + e.getMessage());
                return new byte[0];
            }
        }

        private Instruction decodeInstruction(long address, byte[] bytes) {
            if (bytes.length == 0) {
                return null;
            }
            try {
                Instruction[] instructions = session.emulator().disassemble(address, bytes, false, 1);
                return instructions.length == 0 ? null : instructions[0];
            } catch (RuntimeException e) {
                session.writer().addDiagnostic("count-only instruction decode failed at " + NormalizedTraceModuleResolver.hex(address) + ": " + e.getMessage());
                return null;
            }
        }

        private BranchInfo branch(long address, int size, Instruction instruction) {
            if (instruction == null || instruction.getMnemonic() == null) {
                return null;
            }
            String mnemonic = instruction.getMnemonic().toLowerCase(Locale.ROOT);
            if (!(mnemonic.equals("b") || mnemonic.startsWith("b.") || mnemonic.equals("bl") || mnemonic.equals("blr") || mnemonic.equals("br") || mnemonic.equals("ret") || mnemonic.equals("cbz") || mnemonic.equals("cbnz") || mnemonic.equals("tbz") || mnemonic.equals("tbnz"))) {
                return null;
            }
            return new BranchInfo(true, parseBranchTarget(instruction.getOpStr()), NormalizedTraceModuleResolver.hex(address + size), Collections.<String>emptyList());
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

        private boolean isSvcMemory(long address) {
            if (svcMemoryBase == -1) {
                try {
                    com.github.unidbg.memory.SvcMemory svcMemory = session.emulator().getSvcMemory();
                    if (svcMemory == null) {
                        svcMemoryBase = -2;
                    } else {
                        svcMemoryBase = svcMemory.getBase();
                        svcMemoryEnd = svcMemoryBase + svcMemory.getSize();
                    }
                } catch (RuntimeException ignored) {
                    svcMemoryBase = -2;
                }
            }
            return svcMemoryBase > 0 && address >= svcMemoryBase && address < svcMemoryEnd;
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

    private static final class CountMemoryHook implements ReadHook {
        private final NormalizedTraceSession session;
        private UnHook unHook;

        private CountMemoryHook(NormalizedTraceSession session) {
            this.session = session;
        }

        @Override
        public void hook(Backend backend, long address, int size, Object user) {
            session.writer().countMemoryAccess("read");
            session.stopIfNeeded();
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

    private static final class CountWriteHook implements WriteHook {
        private final CountMemoryHook delegate;
        private UnHook unHook;

        private CountWriteHook(CountMemoryHook delegate) {
            this.delegate = delegate;
        }

        @Override
        public void hook(Backend backend, long address, int size, long value, Object user) {
            delegate.session.writer().countMemoryAccess("write");
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

    private static final class TraceCodeHook implements CodeHook {
        private final NormalizedTraceSession session;
        private final NormalizedTraceModuleResolver resolver;
        private final CachedInstruction[] instructionCache = new CachedInstruction[8192];
        private final Map<Long, CachedInstruction> overflowInstructionCache = new java.util.LinkedHashMap<Long, CachedInstruction>(4096, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Long, CachedInstruction> eldest) {
                return size() > 16384;
            }
        };
        private long svcMemoryBase = -1;
        private long svcMemoryEnd = -1;
        private UnHook unHook;

        private TraceCodeHook(NormalizedTraceSession session) {
            this.session = session;
            this.resolver = new NormalizedTraceModuleResolver(session.emulator(), session.config().targetModule, session.config().targetModuleName);
        }

        @Override
        public void hook(Backend backend, long address, int size, Object user) {
            NormalizedTraceConfig config = session.config();
            if (config.targetModule == null && config.targetModuleName != null && !resolver.contains(address)) {
                flushPrevious(backend, null);
                session.stopIfNeeded();
                return;
            }
            NormalizedTraceRegisters.Snapshot currentRegisters = config.includesRegisters()
                    ? NormalizedTraceRegisters.snapshot(backend, config)
                    : null;
            flushPrevious(backend, currentRegisters);
            if (isSvcMemory(address)) {
                session.pendingInstruction(null);
                session.stopIfNeeded();
                return;
            }
            session.pendingInstruction(buildPendingInstruction(backend, address, size, currentRegisters));
            session.stopIfNeeded();
        }

        private void flushPrevious(Backend backend, NormalizedTraceRegisters.Snapshot currentRegisters) {
            PendingInstruction previous = session.pendingInstruction();
            if (previous != null) {
                previous.flush(session.writer(), currentRegisters);
            }
        }

        private boolean isSvcMemory(long address) {
            if (svcMemoryBase == -1) {
                try {
                    com.github.unidbg.memory.SvcMemory svcMemory = session.emulator().getSvcMemory();
                    if (svcMemory == null) {
                        svcMemoryBase = -2;
                    } else {
                        svcMemoryBase = svcMemory.getBase();
                        svcMemoryEnd = svcMemoryBase + svcMemory.getSize();
                    }
                } catch (RuntimeException ignored) {
                    svcMemoryBase = -2;
                }
            }
            return svcMemoryBase > 0 && address >= svcMemoryBase && address < svcMemoryEnd;
        }

        private PendingInstruction buildPendingInstruction(Backend backend, long address, int size, NormalizedTraceRegisters.Snapshot beforeRegisters) {
            NormalizedTraceConfig config = session.config();
            CachedInstruction instruction = cachedInstruction(backend, address, size);
            Map<String, String> reads = config.includeRegisterReads && instruction.rawInstruction != null
                    ? NormalizedTraceRegisters.reads(session.emulator(), backend, instruction.rawInstruction, beforeRegisters)
                    : Collections.emptyMap();
            return new PendingInstruction(address, resolver.moduleFields(address), instruction, beforeRegisters, reads, config.backendName);
        }

        private CachedInstruction cachedInstruction(Backend backend, long address, int size) {
            int slot = (int) ((address >>> 2) & (instructionCache.length - 1));
            CachedInstruction cached = instructionCache[slot];
            if (cached != null && cached.address == address && cached.size == size) {
                return cached;
            }
            cached = overflowInstructionCache.get(address);
            if (cached != null && cached.size == size) {
                return cached;
            }
            CachedInstruction decoded = decodeCachedInstruction(backend, address, size);
            CachedInstruction old = instructionCache[slot];
            if (old != null && old.address != address) {
                overflowInstructionCache.put(old.address, old);
            }
            instructionCache[slot] = decoded;
            overflowInstructionCache.put(address, decoded);
            return decoded;
        }

        private CachedInstruction decodeCachedInstruction(Backend backend, long address, int size) {
            byte[] bytes = readBytes(backend, address, size);
            Instruction rawInstruction = decodeInstruction(address, bytes);
            String mnemonic = rawInstruction == null ? "unknown" : safeString(rawInstruction.getMnemonic(), "unknown");
            List<String> operands = rawInstruction == null ? Collections.emptyList() : operands(rawInstruction);
            boolean keepRawInstruction = session.config().includeRegisterReads;
            return new CachedInstruction(
                    address,
                    size,
                    Hex.encodeHexString(bytes),
                    mnemonic,
                    operands,
                    branch(address, size, rawInstruction),
                    keepRawInstruction ? rawInstruction : null);
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

        private BranchInfo branch(long address, int size, Instruction instruction) {
            if (instruction == null || instruction.getMnemonic() == null) {
                return null;
            }
            String mnemonic = instruction.getMnemonic().toLowerCase(Locale.ROOT);
            if (!(mnemonic.equals("b") || mnemonic.startsWith("b.") || mnemonic.equals("bl") || mnemonic.equals("blr") || mnemonic.equals("br") || mnemonic.equals("ret") || mnemonic.equals("cbz") || mnemonic.equals("cbnz") || mnemonic.equals("tbz") || mnemonic.equals("tbnz"))) {
                return null;
            }
            String target = parseBranchTarget(instruction.getOpStr());
            return new BranchInfo(true, target, NormalizedTraceModuleResolver.hex(address + size), mnemonic.startsWith("b.") ? Collections.singletonList("nzcv") : Collections.<String>emptyList());
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
            this.resolver = new NormalizedTraceModuleResolver(session.emulator(), session.config().targetModule, session.config().targetModuleName);
        }

        @Override
        public void hook(Backend backend, long address, int size, Object user) {
            writeMemoryEvent(backend, "memory_read", "read_hook", "read", address, size, null);
            session.stopIfNeeded();
        }

        private void writeMemoryEvent(Backend backend, String kind, String rawKind, String access, long address, int size, Long writeValue) {
            MemoryAccess memoryAccess = memoryAccess(backend, access, address, size, writeValue);
            PendingInstruction pending = session.pendingInstruction();
            if (pending != null) {
                pending.addMemoryAccess(memoryAccess);
                session.writer().recordMemoryAccess(access);
                return;
            }
            long pc = readPc(backend);
            session.writer().writeMemoryEvent(kind, resolver.moduleFields(pc), session.config().backendName, rawKind, pc, memoryAccess);
        }

        private MemoryAccess memoryAccess(Backend backend, String access, long address, int size, Long writeValue) {
            return new MemoryAccess(access, address, size, valueHex(backend, access, address, size, writeValue));
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
                return hex(backend.mem_read(address, limit));
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
        int actualSize = Math.max(size, 1);
        char[] out = new char[actualSize * 2];
        for (int i = 0; i < actualSize; i++) {
            int b = (int) ((value >>> (i * 8)) & 0xff);
            out[i * 2] = HEX[b >>> 4];
            out[i * 2 + 1] = HEX[b & 0xf];
        }
        return new String(out);
    }

    private static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            out[i * 2] = HEX[b >>> 4];
            out[i * 2 + 1] = HEX[b & 0xf];
        }
        return new String(out);
    }
}
