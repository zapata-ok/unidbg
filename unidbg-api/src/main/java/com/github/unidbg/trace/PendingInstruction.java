package com.github.unidbg.trace;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

final class PendingInstruction {

    final long pc;
    final ModuleFields moduleFields;
    final CachedInstruction instruction;
    final NormalizedTraceRegisters.Snapshot beforeRegisters;
    final Map<String, String> registerReads;
    final String backendName;
    final List<MemoryAccess> memoryAccesses = new ArrayList<>();

    PendingInstruction(long pc, ModuleFields moduleFields, CachedInstruction instruction,
                       NormalizedTraceRegisters.Snapshot beforeRegisters, Map<String, String> registerReads,
                       String backendName) {
        this.pc = pc;
        this.moduleFields = moduleFields;
        this.instruction = instruction;
        this.beforeRegisters = beforeRegisters;
        this.registerReads = registerReads;
        this.backendName = backendName;
    }

    void addMemoryAccess(MemoryAccess memoryAccess) {
        memoryAccesses.add(memoryAccess);
    }

    void flush(NormalizedTraceWriter writer, NormalizedTraceRegisters.Snapshot afterRegisters) {
        writer.writeInstruction(this, afterRegisters);
    }
}
