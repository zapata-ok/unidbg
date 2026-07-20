package com.github.unidbg.trace;

import com.github.unidbg.Module;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class NormalizedTraceConfig {

    public enum Level {
        OFF,
        INSTRUCTION,
        REGISTERS,
        MEMORY,
        FULL
    }

    public final String caseId;
    public final File outputDir;
    public final String backendName;
    public final Level level;
    public final long maxEvents;
    public final long maxEventFileBytes;
    public final Module targetModule;
    public final long traceBegin;
    public final long traceEnd;
    public final List<AddressRange> memoryRanges;
    public final Map<String, Integer> selectedRegisters;
    public final int memoryValueLimit;
    public final boolean includeInstructionBytes;
    public final boolean includeInstructionDecode;
    public final boolean includeRegisterReads;
    public final boolean includeRegisterWrites;
    public final boolean includeMemoryValues;
    public final boolean stopEmulatorOnMaxEvents;

    private NormalizedTraceConfig(Builder builder) {
        this.caseId = builder.caseId;
        this.outputDir = builder.outputDir;
        this.backendName = builder.backendName;
        this.level = builder.level;
        this.maxEvents = builder.maxEvents;
        this.maxEventFileBytes = builder.maxEventFileBytes;
        this.targetModule = builder.targetModule;
        this.traceBegin = builder.traceBegin;
        this.traceEnd = builder.traceEnd;
        this.memoryRanges = Collections.unmodifiableList(new ArrayList<>(builder.memoryRanges));
        this.selectedRegisters = Collections.unmodifiableMap(new LinkedHashMap<>(builder.selectedRegisters));
        this.memoryValueLimit = builder.memoryValueLimit;
        this.includeInstructionBytes = builder.includeInstructionBytes;
        this.includeInstructionDecode = builder.includeInstructionDecode;
        this.includeRegisterReads = builder.includeRegisterReads;
        this.includeRegisterWrites = builder.includeRegisterWrites;
        this.includeMemoryValues = builder.includeMemoryValues;
        this.stopEmulatorOnMaxEvents = builder.stopEmulatorOnMaxEvents;
    }

    public boolean includesInstruction() {
        return level == Level.INSTRUCTION || level == Level.REGISTERS || level == Level.MEMORY || level == Level.FULL;
    }

    public boolean includesRegisters() {
        return level == Level.REGISTERS || level == Level.FULL;
    }

    public boolean includesMemory() {
        return level == Level.MEMORY || level == Level.FULL;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Map<String, Integer> arm64GprAll() {
        LinkedHashMap<String, Integer> regs = new LinkedHashMap<>();
        regs.put("x0", Arm64Const.UC_ARM64_REG_X0);
        regs.put("x1", Arm64Const.UC_ARM64_REG_X1);
        regs.put("x2", Arm64Const.UC_ARM64_REG_X2);
        regs.put("x3", Arm64Const.UC_ARM64_REG_X3);
        regs.put("x4", Arm64Const.UC_ARM64_REG_X4);
        regs.put("x5", Arm64Const.UC_ARM64_REG_X5);
        regs.put("x6", Arm64Const.UC_ARM64_REG_X6);
        regs.put("x7", Arm64Const.UC_ARM64_REG_X7);
        regs.put("x8", Arm64Const.UC_ARM64_REG_X8);
        regs.put("x9", Arm64Const.UC_ARM64_REG_X9);
        regs.put("x10", Arm64Const.UC_ARM64_REG_X10);
        regs.put("x11", Arm64Const.UC_ARM64_REG_X11);
        regs.put("x12", Arm64Const.UC_ARM64_REG_X12);
        regs.put("x13", Arm64Const.UC_ARM64_REG_X13);
        regs.put("x14", Arm64Const.UC_ARM64_REG_X14);
        regs.put("x15", Arm64Const.UC_ARM64_REG_X15);
        regs.put("x16", Arm64Const.UC_ARM64_REG_X16);
        regs.put("x17", Arm64Const.UC_ARM64_REG_X17);
        regs.put("x18", Arm64Const.UC_ARM64_REG_X18);
        regs.put("x19", Arm64Const.UC_ARM64_REG_X19);
        regs.put("x20", Arm64Const.UC_ARM64_REG_X20);
        regs.put("x21", Arm64Const.UC_ARM64_REG_X21);
        regs.put("x22", Arm64Const.UC_ARM64_REG_X22);
        regs.put("x23", Arm64Const.UC_ARM64_REG_X23);
        regs.put("x24", Arm64Const.UC_ARM64_REG_X24);
        regs.put("x25", Arm64Const.UC_ARM64_REG_X25);
        regs.put("x26", Arm64Const.UC_ARM64_REG_X26);
        regs.put("x27", Arm64Const.UC_ARM64_REG_X27);
        regs.put("x28", Arm64Const.UC_ARM64_REG_X28);
        regs.put("x29", Arm64Const.UC_ARM64_REG_X29);
        regs.put("x30", Arm64Const.UC_ARM64_REG_LR);
        regs.put("sp", Arm64Const.UC_ARM64_REG_SP);
        regs.put("pc", Arm64Const.UC_ARM64_REG_PC);
        regs.put("nzcv", Arm64Const.UC_ARM64_REG_NZCV);
        return regs;
    }

    public static Map<String, Integer> arm64GprFast() {
        LinkedHashMap<String, Integer> regs = new LinkedHashMap<>();
        Map<String, Integer> all = arm64GprAll();
        for (int i = 0; i <= 15; i++) {
            regs.put("x" + i, all.get("x" + i));
        }
        regs.put("sp", all.get("sp"));
        regs.put("pc", all.get("pc"));
        regs.put("nzcv", all.get("nzcv"));
        return regs;
    }

    public static Map<String, Integer> arm32GprAll() {
        LinkedHashMap<String, Integer> regs = new LinkedHashMap<>();
        regs.put("r0", ArmConst.UC_ARM_REG_R0);
        regs.put("r1", ArmConst.UC_ARM_REG_R1);
        regs.put("r2", ArmConst.UC_ARM_REG_R2);
        regs.put("r3", ArmConst.UC_ARM_REG_R3);
        regs.put("r4", ArmConst.UC_ARM_REG_R4);
        regs.put("r5", ArmConst.UC_ARM_REG_R5);
        regs.put("r6", ArmConst.UC_ARM_REG_R6);
        regs.put("r7", ArmConst.UC_ARM_REG_R7);
        regs.put("r8", ArmConst.UC_ARM_REG_R8);
        regs.put("r9", ArmConst.UC_ARM_REG_R9);
        regs.put("r10", ArmConst.UC_ARM_REG_R10);
        regs.put("r11", ArmConst.UC_ARM_REG_R11);
        regs.put("r12", ArmConst.UC_ARM_REG_R12);
        regs.put("sp", ArmConst.UC_ARM_REG_SP);
        regs.put("lr", ArmConst.UC_ARM_REG_LR);
        regs.put("pc", ArmConst.UC_ARM_REG_PC);
        regs.put("cpsr", ArmConst.UC_ARM_REG_CPSR);
        return regs;
    }

    public static final class Builder {
        private String caseId = "case_0";
        private File outputDir = new File("out");
        private String backendName = "unidbg";
        private Level level = Level.INSTRUCTION;
        private long maxEvents = 1_000_000L;
        private long maxEventFileBytes = 0L;
        private Module targetModule;
        private long traceBegin = 1;
        private long traceEnd = 0;
        private final List<AddressRange> memoryRanges = new ArrayList<>();
        private Map<String, Integer> selectedRegisters = arm64GprAll();
        private int memoryValueLimit = 16;
        private boolean includeInstructionBytes = true;
        private boolean includeInstructionDecode = true;
        private boolean includeRegisterReads = false;
        private boolean includeRegisterWrites = true;
        private boolean includeMemoryValues = true;
        private boolean stopEmulatorOnMaxEvents = true;

        public Builder caseId(String caseId) {
            this.caseId = caseId;
            return this;
        }

        public Builder outputDir(File outputDir) {
            this.outputDir = outputDir;
            return this;
        }

        public Builder backendName(String backendName) {
            this.backendName = backendName;
            return this;
        }

        public Builder level(Level level) {
            this.level = level;
            return this;
        }

        public Builder maxEvents(long maxEvents) {
            this.maxEvents = maxEvents;
            return this;
        }

        public Builder maxEventFileBytes(long maxEventFileBytes) {
            this.maxEventFileBytes = maxEventFileBytes;
            return this;
        }

        public Builder targetModule(Module targetModule) {
            this.targetModule = targetModule;
            if (targetModule != null) {
                this.traceBegin = targetModule.base;
                this.traceEnd = targetModule.base + targetModule.size;
            }
            return this;
        }

        public Builder traceRange(long begin, long end) {
            this.traceBegin = begin;
            this.traceEnd = end;
            return this;
        }

        public Builder addMemoryRange(long begin, long end) {
            this.memoryRanges.add(new AddressRange(begin, end));
            return this;
        }

        public Builder selectedRegisters(Map<String, Integer> selectedRegisters) {
            this.selectedRegisters = selectedRegisters;
            return this;
        }

        public Builder memoryValueLimit(int memoryValueLimit) {
            this.memoryValueLimit = memoryValueLimit;
            return this;
        }

        public Builder includeInstructionBytes(boolean includeInstructionBytes) {
            this.includeInstructionBytes = includeInstructionBytes;
            return this;
        }

        public Builder includeInstructionDecode(boolean includeInstructionDecode) {
            this.includeInstructionDecode = includeInstructionDecode;
            return this;
        }

        public Builder includeRegisterReads(boolean includeRegisterReads) {
            this.includeRegisterReads = includeRegisterReads;
            return this;
        }

        public Builder includeRegisterWrites(boolean includeRegisterWrites) {
            this.includeRegisterWrites = includeRegisterWrites;
            return this;
        }

        public Builder includeMemoryValues(boolean includeMemoryValues) {
            this.includeMemoryValues = includeMemoryValues;
            return this;
        }

        public Builder stopEmulatorOnMaxEvents(boolean stopEmulatorOnMaxEvents) {
            this.stopEmulatorOnMaxEvents = stopEmulatorOnMaxEvents;
            return this;
        }

        public NormalizedTraceConfig build() {
            if (caseId == null || caseId.isEmpty()) {
                throw new IllegalArgumentException("caseId is required");
            }
            if (outputDir == null) {
                throw new IllegalArgumentException("outputDir is required");
            }
            if (backendName == null || backendName.isEmpty()) {
                backendName = "unidbg";
            }
            if (level == null) {
                level = Level.INSTRUCTION;
            }
            if (selectedRegisters == null) {
                selectedRegisters = arm64GprAll();
            }
            return new NormalizedTraceConfig(this);
        }
    }
}
