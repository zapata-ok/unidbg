package com.github.unidbg.trace;

import java.util.LinkedHashMap;
import java.util.Map;

final class PendingInstruction {

    private final Map<String, Object> event;
    private final Map<String, String> beforeRegisters;
    private final Map<String, String> registerReads;

    PendingInstruction(Map<String, Object> event, Map<String, String> beforeRegisters, Map<String, String> registerReads) {
        this.event = event;
        this.beforeRegisters = beforeRegisters;
        this.registerReads = registerReads;
    }

    void flush(NormalizedTraceWriter writer, Map<String, String> afterRegisters) {
        Map<String, String> writes = afterRegisters == null ? new LinkedHashMap<>() : NormalizedTraceRegisters.delta(beforeRegisters, afterRegisters);
        Map<String, Object> registers = new LinkedHashMap<>();
        registers.put("reads", registerReads);
        registers.put("writes", writes);
        event.put("registers", registers);
        writer.writeEvent("instruction", event);
    }
}
