package com.github.unidbg.trace;

import com.alibaba.fastjson.JSON;

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

final class NormalizedTraceWriter implements Closeable {

    private final NormalizedTraceConfig config;
    private final File eventFile;
    private final BufferedWriter writer;
    private final BinaryTraceWriter binaryWriter;
    private final BlockingQueue<String> queue = new ArrayBlockingQueue<>(8192);
    private final Thread writerThread;
    private final NormalizedTraceCounters counters = new NormalizedTraceCounters();
    private final List<String> diagnostics = new ArrayList<>();
    private static final String POISON = new String("normalized-trace-writer-poison");
    private long seq;
    private boolean closed;

    NormalizedTraceWriter(NormalizedTraceConfig config) throws IOException {
        this.config = config;
        if (!config.outputDir.exists() && !config.outputDir.mkdirs()) {
            throw new IOException("failed to create trace output directory: " + config.outputDir);
        }
        boolean jsonlEnabled = config.outputFormat == TraceOutputFormat.JSONL || config.outputFormat == TraceOutputFormat.BOTH;
        boolean binaryEnabled = config.outputFormat == TraceOutputFormat.BINARY || config.outputFormat == TraceOutputFormat.BOTH;
        this.eventFile = new File(config.outputDir, "events." + config.caseId + ".000.jsonl");
        this.writer = jsonlEnabled ? new BufferedWriter(new FileWriter(eventFile)) : null;
        this.binaryWriter = binaryEnabled ? new BinaryTraceWriter(config) : null;
        this.writerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                drainQueue();
            }
        }, "NormalizedTraceWriter");
        this.writerThread.setDaemon(true);
        if (jsonlEnabled) {
            this.writerThread.start();
        }
    }

    boolean writeEvent(String kind, Map<String, Object> event) {
        if (closed) {
            counters.droppedEvents++;
            return false;
        }
        if (config.maxEvents > 0 && counters.events >= config.maxEvents) {
            counters.droppedEvents++;
            return false;
        }
        try {
            seq++;
            event.put("seq", seq);
            if (writer != null) {
                enqueue(JSON.toJSONString(event));
            }
            counters.events++;
            if ("instruction".equals(kind)) {
                counters.instructions++;
                if (event.get("branch") != null) {
                    counters.branches++;
                }
                Object registers = event.get("registers");
                if (registers instanceof Map) {
                    Object writes = ((Map<?, ?>) registers).get("writes");
                    if (writes instanceof Map && !((Map<?, ?>) writes).isEmpty()) {
                        counters.registerWrites++;
                    }
                }
            } else if ("memory_read".equals(kind)) {
                counters.memoryReads++;
            } else if ("memory_write".equals(kind)) {
                counters.memoryWrites++;
            } else if ("branch".equals(kind)) {
                counters.branches++;
            }
            return true;
        } catch (RuntimeException e) {
            diagnostics.add("write trace event failed: " + e.getMessage());
            counters.droppedEvents++;
            return false;
        }
    }

    boolean writeInstruction(PendingInstruction instruction, NormalizedTraceRegisters.Snapshot afterRegisters) {
        if (closed) {
            counters.droppedEvents++;
            return false;
        }
        if (config.maxEvents > 0 && counters.events >= config.maxEvents) {
            counters.droppedEvents++;
            return false;
        }
        long currentSeq = ++seq;
        StringBuilder sb = new StringBuilder(512 + instruction.memoryAccesses.size() * 96);
        sb.append('{');
        appendStringField(sb, "thread_id", "main");
        appendCommaStringField(sb, "kind", "instruction");
        appendCommaStringField(sb, "pc", NormalizedTraceModuleResolver.hex(instruction.pc));
        appendCommaStringFieldOrNull(sb, "module", instruction.moduleFields.moduleName);
        appendCommaStringFieldOrNull(sb, "file_offset", instruction.moduleFields.fileOffset);
        if (instruction.moduleFields.symbol != null) {
            appendCommaStringField(sb, "symbol", instruction.moduleFields.symbol);
        }
        sb.append(",\"instruction\":{");
        appendStringField(sb, "bytes", config.includeInstructionBytes ? instruction.instruction.bytesHex : "");
        appendCommaStringField(sb, "mnemonic", instruction.instruction.mnemonic);
        sb.append(",\"operands\":[");
        for (int i = 0; i < instruction.instruction.operands.size(); i++) {
            if (i > 0) sb.append(',');
            appendJsonString(sb, instruction.instruction.operands.get(i));
        }
        sb.append("]}");
        sb.append(",\"memory\":[");
        for (int i = 0; i < instruction.memoryAccesses.size(); i++) {
            if (i > 0) sb.append(',');
            appendMemoryAccess(sb, instruction.memoryAccesses.get(i));
        }
        sb.append(']');
        if (instruction.instruction.branch != null) {
            appendBranch(sb, instruction.instruction.branch);
        }
        sb.append(",\"backend\":{");
        appendStringField(sb, "name", instruction.backendName);
        appendCommaStringField(sb, "raw_kind", "code_hook");
        sb.append('}');
        appendRegisters(sb, instruction, afterRegisters);
        sb.append(",\"seq\":").append(currentSeq).append('}');
        if (writer != null) {
            enqueue(sb.toString());
        }
        try {
            if (binaryWriter != null) {
                binaryWriter.writeInstruction(currentSeq, instruction, afterRegisters);
            }
        } catch (IOException e) {
            diagnostics.add("write binary trace event failed: " + e.getMessage());
            counters.droppedEvents++;
            return false;
        }
        counters.events++;
        counters.instructions++;
        if (instruction.instruction.branch != null) {
            counters.branches++;
        }
        counters.registerWrites += countRegisterWrites(instruction.beforeRegisters, afterRegisters);
        return true;
    }

    boolean writeMemoryEvent(String kind, ModuleFields moduleFields, String backendName, String rawKind, long pc, MemoryAccess access) {
        if (closed) {
            counters.droppedEvents++;
            return false;
        }
        if (config.maxEvents > 0 && counters.events >= config.maxEvents) {
            counters.droppedEvents++;
            return false;
        }
        long currentSeq = ++seq;
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        appendStringField(sb, "thread_id", "main");
        appendCommaStringField(sb, "kind", kind);
        appendCommaStringField(sb, "pc", NormalizedTraceModuleResolver.hex(pc));
        if (moduleFields != null) {
            appendCommaStringFieldOrNull(sb, "module", moduleFields.moduleName);
            appendCommaStringFieldOrNull(sb, "file_offset", moduleFields.fileOffset);
            if (moduleFields.symbol != null) {
                appendCommaStringField(sb, "symbol", moduleFields.symbol);
            }
        }
        sb.append(",\"backend\":{");
        appendStringField(sb, "name", backendName);
        appendCommaStringField(sb, "raw_kind", rawKind);
        sb.append('}');
        sb.append(",\"memory\":[");
        appendMemoryAccess(sb, access);
        sb.append(']');
        sb.append(",\"seq\":").append(currentSeq).append('}');
        if (writer != null) {
            enqueue(sb.toString());
        }
        try {
            if (binaryWriter != null) {
                binaryWriter.writeMemoryEvent(currentSeq, kind, moduleFields, pc, access);
            }
        } catch (IOException e) {
            diagnostics.add("write binary trace event failed: " + e.getMessage());
            counters.droppedEvents++;
            return false;
        }
        counters.events++;
        if ("memory_read".equals(kind)) {
            counters.memoryReads++;
        } else if ("memory_write".equals(kind)) {
            counters.memoryWrites++;
        }
        return true;
    }

    private void appendRegisters(StringBuilder sb, PendingInstruction instruction, NormalizedTraceRegisters.Snapshot afterRegisters) {
        sb.append(",\"registers\":{");
        sb.append("\"reads\":{");
        int emitted = 0;
        for (Map.Entry<String, String> entry : instruction.registerReads.entrySet()) {
            if (emitted++ > 0) sb.append(',');
            appendJsonString(sb, entry.getKey());
            sb.append(':');
            appendJsonString(sb, entry.getValue());
        }
        sb.append("},\"writes\":{");
        if (afterRegisters != null && instruction.beforeRegisters != null) {
            emitted = 0;
            int len = Math.min(instruction.beforeRegisters.names.length, afterRegisters.names.length);
            for (int i = 0; i < len; i++) {
                if (!instruction.beforeRegisters.valid[i] || !afterRegisters.valid[i]) {
                    continue;
                }
                if (instruction.beforeRegisters.values[i] == afterRegisters.values[i]) {
                    continue;
                }
                if (emitted++ > 0) sb.append(',');
                appendJsonString(sb, afterRegisters.names[i]);
                sb.append(':');
                appendJsonString(sb, NormalizedTraceModuleResolver.hex(afterRegisters.values[i]));
            }
        }
        sb.append("}}");
    }

    private int countRegisterWrites(NormalizedTraceRegisters.Snapshot before, NormalizedTraceRegisters.Snapshot after) {
        if (before == null || after == null) {
            return 0;
        }
        int count = 0;
        int len = Math.min(before.names.length, after.names.length);
        for (int i = 0; i < len; i++) {
            if (before.valid[i] && after.valid[i] && before.values[i] != after.values[i]) {
                count++;
            }
        }
        return count;
    }

    private void appendMemoryAccess(StringBuilder sb, MemoryAccess access) {
        sb.append('{');
        appendStringField(sb, "access", access.access);
        appendCommaStringField(sb, "address", NormalizedTraceModuleResolver.hex(access.address));
        sb.append(",\"size\":").append(access.size);
        sb.append(",\"value_hex\":");
        if (access.valueHex == null) {
            sb.append("null");
        } else {
            appendJsonString(sb, access.valueHex);
        }
        sb.append(",\"taint\":[]}");
    }

    private void appendBranch(StringBuilder sb, BranchInfo branch) {
        sb.append(",\"branch\":{");
        sb.append("\"taken\":").append(branch.taken);
        sb.append(",\"target\":");
        if (branch.target == null) {
            appendJsonString(sb, "");
        } else {
            appendJsonString(sb, branch.target);
        }
        appendCommaStringField(sb, "fallthrough", branch.fallthrough);
        sb.append(",\"condition_registers\":[");
        for (int i = 0; i < branch.conditionRegisters.size(); i++) {
            if (i > 0) sb.append(',');
            appendJsonString(sb, branch.conditionRegisters.get(i));
        }
        sb.append("]}");
    }

    private void appendStringField(StringBuilder sb, String key, String value) {
        appendJsonString(sb, key);
        sb.append(':');
        appendJsonString(sb, value);
    }

    private void appendCommaStringField(StringBuilder sb, String key, String value) {
        sb.append(',');
        appendStringField(sb, key, value);
    }

    private void appendCommaStringFieldOrNull(StringBuilder sb, String key, String value) {
        sb.append(',');
        appendJsonString(sb, key);
        sb.append(':');
        if (value == null) {
            sb.append("null");
        } else {
            appendJsonString(sb, value);
        }
    }

    private void appendJsonString(StringBuilder sb, String value) {
        sb.append('"');
        if (value != null) {
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c == '"' || c == '\\') {
                    sb.append('\\').append(c);
                } else if (c == '\n') {
                    sb.append("\\n");
                } else if (c == '\r') {
                    sb.append("\\r");
                } else if (c == '\t') {
                    sb.append("\\t");
                } else if (c < 0x20) {
                    sb.append("\\u00");
                    String hex = Integer.toHexString(c);
                    if (hex.length() == 1) sb.append('0');
                    sb.append(hex);
                } else {
                    sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    private void enqueue(String line) {
        try {
            queue.put(line);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private void drainQueue() {
        try {
            while (true) {
                String line = queue.take();
                if (POISON == line) {
                    break;
                }
                if (writer != null) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            if (writer != null) {
                writer.flush();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            diagnostics.add("trace writer interrupted");
        } catch (IOException e) {
            diagnostics.add("write trace event failed: " + e.getMessage());
        }
    }

    void flushEvents() {
        while (!queue.isEmpty()) {
            try {
                Thread.sleep(1L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                diagnostics.add("trace writer flush interrupted");
                return;
            }
        }
    }

    void addDiagnostic(String diagnostic) {
        diagnostics.add(diagnostic);
    }

    NormalizedTraceCounters counters() {
        return counters.snapshot();
    }

    void recordMemoryAccess(String access) {
        if ("read".equals(access)) {
            counters.memoryReads++;
        } else if ("write".equals(access)) {
            counters.memoryWrites++;
        }
        if (binaryWriter != null) {
            binaryWriter.recordMemoryAccess(access);
        }
    }

    List<String> diagnostics() {
        return Collections.unmodifiableList(diagnostics);
    }

    File eventFile() {
        return eventFile;
    }

    String eventFileName() {
        return eventFile.getName();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        if (writer != null) {
            enqueue(POISON);
            try {
                writerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("trace writer close interrupted", e);
            }
            writer.close();
        }
        if (binaryWriter != null) {
            binaryWriter.close();
        }
    }

    void writeBinaryMetadata() throws IOException {
        if (binaryWriter != null) {
            binaryWriter.writeMetadata();
        }
    }

    void writeSessionSummary(String status) throws IOException {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("schema_version", "0.1");
        summary.put("kind", "normalized_trace_session");
        summary.put("status", status);
        summary.put("case_id", config.caseId);
        List<Map<String, Object>> files = new ArrayList<>();
        if (writer != null) {
            Map<String, Object> file = new LinkedHashMap<>();
            file.put("path", eventFileName());
            file.put("format", "jsonl");
            file.put("event_schema", "trace_event.v0.1");
            file.put("status", counters.events > 0 ? "collected" : "empty");
            file.put("compression", "none");
            files.add(file);
        }
        if (binaryWriter != null) {
            Map<String, Object> file = new LinkedHashMap<>();
            if (binaryWriter.eventFileNames().size() <= 1) {
                file.put("path", binaryWriter.eventFileName());
            } else {
                file.put("paths", binaryWriter.eventFileNames());
            }
            file.put("format", BinaryTraceWriter.FORMAT);
            file.put("event_schema", "trace_event_binary.v0.2");
            file.put("status", counters.events > 0 ? "collected" : "empty");
            file.put("compression", "none");
            files.add(file);
        }
        summary.put("event_files", files);
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("events", counters.events);
        counts.put("instructions", counters.instructions);
        counts.put("branches", counters.branches);
        counts.put("memory_reads", counters.memoryReads);
        counts.put("memory_writes", counters.memoryWrites);
        counts.put("register_writes", counters.registerWrites);
        counts.put("dropped_events", counters.droppedEvents);
        counts.put("malformed_events", 0);
        summary.put("summary", counts);
        summary.put("diagnostics", diagnostics);
        File summaryFile = new File(config.outputDir, "normalized_trace_session.json");
        try (BufferedWriter out = new BufferedWriter(new FileWriter(summaryFile))) {
            out.write(JSON.toJSONString(summary, true));
            out.newLine();
        }
    }
}
