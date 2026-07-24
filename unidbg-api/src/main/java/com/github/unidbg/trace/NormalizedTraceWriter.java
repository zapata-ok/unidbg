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
        this.eventFile = new File(config.outputDir, "events." + config.caseId + ".000.jsonl");
        this.writer = new BufferedWriter(new FileWriter(eventFile));
        this.writerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                drainQueue();
            }
        }, "NormalizedTraceWriter");
        this.writerThread.setDaemon(true);
        this.writerThread.start();
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
            enqueue(JSON.toJSONString(event));
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
                writer.write(line);
                writer.newLine();
            }
            writer.flush();
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
        enqueue(POISON);
        try {
            writerThread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("trace writer close interrupted", e);
        }
        writer.close();
    }

    void writeSessionSummary(String status) throws IOException {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("schema_version", "0.1");
        summary.put("kind", "normalized_trace_session");
        summary.put("status", status);
        summary.put("case_id", config.caseId);
        List<Map<String, Object>> files = new ArrayList<>();
        Map<String, Object> file = new LinkedHashMap<>();
        file.put("path", eventFileName());
        file.put("format", "jsonl");
        file.put("event_schema", "trace_event.v0.1");
        file.put("status", counters.events > 0 ? "collected" : "empty");
        file.put("compression", "none");
        files.add(file);
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
