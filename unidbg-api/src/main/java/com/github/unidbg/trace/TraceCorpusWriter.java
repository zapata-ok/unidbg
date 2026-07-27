package com.github.unidbg.trace;

import com.alibaba.fastjson.JSON;
import com.github.unidbg.Module;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class TraceCorpusWriter {

    private final File outputDir;
    private String toolName = "unidbg";
    private String toolVersion;
    private String producerMode = "unidbg_trace";
    private String targetPath;
    private String targetFormat = "elf";
    private String targetArch = "arm64";
    private String targetEntry = "";
    private String processName;
    private int apiLevel;
    private final List<String> assumptions = new ArrayList<>();
    private final List<TraceModule> modules = new ArrayList<>();
    private final List<TraceCase> cases = new ArrayList<>();
    private final List<String> diagnostics = new ArrayList<>();

    public TraceCorpusWriter(File outputDir) {
        this.outputDir = outputDir;
    }

    public TraceCorpusWriter tool(String name, String version) {
        this.toolName = name;
        this.toolVersion = version;
        return this;
    }

    public TraceCorpusWriter producerMode(String producerMode) {
        this.producerMode = producerMode;
        return this;
    }

    public TraceCorpusWriter target(String path, String format, String arch, String entry) {
        this.targetPath = path;
        this.targetFormat = format;
        this.targetArch = arch;
        this.targetEntry = entry == null ? "" : entry;
        return this;
    }

    public TraceCorpusWriter environment(String processName, int apiLevel) {
        this.processName = processName;
        this.apiLevel = apiLevel;
        return this;
    }

    public TraceCorpusWriter assumption(String assumption) {
        if (assumption != null && !assumption.isEmpty()) {
            assumptions.add(assumption);
        }
        return this;
    }

    public TraceCorpusWriter addModule(Module module, String path) {
        if (module != null) {
            modules.add(new TraceModule(module.name, module.base, module.size, path));
        }
        return this;
    }

    public TraceCorpusWriter addModule(String name, long base, long size, String path) {
        modules.add(new TraceModule(name, base, size, path));
        return this;
    }

    public TraceCorpusWriter diagnostic(String diagnostic) {
        if (diagnostic != null && !diagnostic.isEmpty()) {
            diagnostics.add(diagnostic);
        }
        return this;
    }

    public TraceCorpusWriter addCase(TraceCase traceCase) {
        cases.add(traceCase);
        return this;
    }

    public TraceCorpusWriter addCase(String caseId, String phase, String status, NormalizedTraceSession session) {
        return addCase(TraceCase.builder(caseId, phase).status(status).session(session).build());
    }

    public void write() throws IOException {
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            throw new IOException("failed to create trace corpus output directory: " + outputDir);
        }
        writeJson(new File(outputDir, "trace_corpus.json"), traceCorpus());
        writeJson(new File(outputDir, "trace_index.json"), traceIndex());
        writeJson(new File(outputDir, "trace_summary.json"), traceSummary("indexed"));
    }

    private Map<String, Object> traceCorpus() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schema_version", "0.1");
        out.put("kind", "trace_corpus");
        out.put("tool", mapOf("name", toolName, "version", toolVersion));
        out.put("producer", mapOf("backend", "unidbg", "backend_version", null, "mode", producerMode, "normalized", true));

        Map<String, Object> target = new LinkedHashMap<>();
        target.put("path", targetPath);
        target.put("format", targetFormat);
        target.put("arch", targetArch);
        target.put("entry", targetEntry == null ? "" : targetEntry);
        target.put("assumptions", assumptions);
        out.put("target", target);

        Map<String, Object> environment = new LinkedHashMap<>();
        environment.put("os", "android-unidbg");
        environment.put("api_level", apiLevel);
        environment.put("abi", "arm64-v8a");
        environment.put("process", processName);
        environment.put("modules", moduleMaps());
        environment.put("hooks", Collections.singletonList(mapOf(
                "kind", "normalized_trace",
                "target", "configured_trace_range",
                "behavior", "records instruction/register/memory events without modifying execution")));
        out.put("environment", environment);
        out.put("capture", captureMap());

        List<Map<String, Object>> caseMaps = new ArrayList<>();
        for (TraceCase traceCase : cases) {
            caseMaps.add(traceCase.toCorpusMap(outputDir));
        }
        out.put("cases", caseMaps);
        out.put("artifacts", artifacts());
        return out;
    }

    private Map<String, Object> captureMap() {
        Map<String, Object> memory = new LinkedHashMap<>();
        memory.put("enabled", true);
        memory.put("metadata", true);
        memory.put("values", true);
        memory.put("default_value_limit", 16);
        memory.put("rationale", "unidbg normalized trace captures events according to each phase trace level");

        Map<String, Object> capture = new LinkedHashMap<>();
        capture.put("level", "phase_configured");
        capture.put("pc_granularity", "instruction");
        capture.put("registers", "selected_delta");
        capture.put("selected_registers", arm64SelectedRegisters());
        capture.put("branch_outcomes", totalCounters().branches > 0);
        capture.put("memory", memory);
        capture.put("filters", Collections.singletonList("configured_trace_range"));
        return capture;
    }

    private Map<String, Object> traceIndex() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schema_version", "0.1");
        out.put("kind", "trace_index");
        out.put("source_trace", "trace_corpus.json");
        out.put("summary", traceSummary("indexed"));
        List<Map<String, Object>> chunks = new ArrayList<>();
        for (TraceCase traceCase : cases) {
            for (Map<String, Object> file : traceCase.traceFiles(outputDir)) {
                Map<String, Object> chunk = new LinkedHashMap<>();
                chunk.put("path", file.get("path"));
                chunk.put("case_id", traceCase.caseId);
                chunk.put("format", file.get("format"));
                chunk.put("events", traceCase.counters.events);
                chunk.put("seq_start", traceCase.counters.events > 0 ? 1 : null);
                chunk.put("seq_end", traceCase.counters.events > 0 ? traceCase.counters.events : null);
                chunks.add(chunk);
            }
        }
        out.put("chunks", chunks);
        out.put("diagnostics", allDiagnostics());
        return out;
    }

    private Map<String, Object> traceSummary(String status) {
        NormalizedTraceCounters total = totalCounters();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schema_version", "0.1");
        out.put("kind", "trace_summary");
        out.put("status", status);
        out.put("cases", cases.size());
        out.put("chunks", countTraceFiles());
        out.put("indexed_chunks", countTraceFiles());
        out.put("events", total.events);
        out.put("instructions", total.instructions);
        out.put("basic_blocks", 0);
        out.put("branches", total.branches);
        out.put("memory_reads", total.memoryReads);
        out.put("memory_writes", total.memoryWrites);
        out.put("register_writes", total.registerWrites);
        out.put("malformed_lines", 0);
        out.put("missing_chunks", 0);
        out.put("unsupported_chunks", 0);
        out.put("diagnostics", allDiagnostics());
        return out;
    }

    private List<Map<String, Object>> artifacts() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (TraceCase traceCase : cases) {
            out.addAll(traceCase.artifacts(outputDir));
        }
        out.add(mapOf("name", "trace_index", "path", "trace_index.json", "kind", "json"));
        out.add(mapOf("name", "trace_summary", "path", "trace_summary.json", "kind", "json"));
        return out;
    }

    private List<Map<String, Object>> moduleMaps() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (TraceModule module : modules) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", module.name);
            item.put("base", hex(module.base));
            item.put("size", hex(module.size));
            item.put("path", module.path);
            out.add(item);
        }
        return out;
    }

    private NormalizedTraceCounters totalCounters() {
        NormalizedTraceCounters total = new NormalizedTraceCounters();
        for (TraceCase traceCase : cases) {
            total.events += traceCase.counters.events;
            total.instructions += traceCase.counters.instructions;
            total.branches += traceCase.counters.branches;
            total.memoryReads += traceCase.counters.memoryReads;
            total.memoryWrites += traceCase.counters.memoryWrites;
            total.registerWrites += traceCase.counters.registerWrites;
            total.droppedEvents += traceCase.counters.droppedEvents;
        }
        return total;
    }

    private int countTraceFiles() {
        int count = 0;
        for (TraceCase traceCase : cases) {
            count += traceCase.traceFiles(outputDir).size();
        }
        return count;
    }

    private List<String> allDiagnostics() {
        List<String> out = new ArrayList<>(diagnostics);
        for (TraceCase traceCase : cases) {
            out.addAll(traceCase.diagnostics);
        }
        return out;
    }

    private void writeJson(File file, Object value) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(JSON.toJSONString(value, true));
            writer.newLine();
        }
    }

    private static List<String> binaryTraceFileNames(File outputDir, String caseId) {
        File[] files = outputDir.listFiles();
        if (files == null) {
            return Collections.emptyList();
        }
        List<String> names = new ArrayList<>();
        String prefix = "trace." + caseId + ".";
        for (File file : files) {
            if (file.isFile() && file.getName().startsWith(prefix) && file.getName().endsWith(".bin")) {
                names.add(file.getName());
            }
        }
        Collections.sort(names);
        return names;
    }

    private static Map<String, Object> mapOf(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            map.put(String.valueOf(pairs[i]), pairs[i + 1]);
        }
        return map;
    }

    private static List<String> arm64SelectedRegisters() {
        List<String> registers = new ArrayList<>();
        for (int i = 0; i <= 30; i++) {
            registers.add("x" + i);
        }
        registers.add("sp");
        registers.add("pc");
        registers.add("nzcv");
        return registers;
    }

    private static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private static final class TraceModule {
        private final String name;
        private final long base;
        private final long size;
        private final String path;

        private TraceModule(String name, long base, long size, String path) {
            this.name = name;
            this.base = base;
            this.size = size;
            this.path = path;
        }
    }

    public static final class TraceCase {
        private final String caseId;
        private final String phase;
        private final String status;
        private final String entryStatus;
        private final String entryAddress;
        private final String returnValue;
        private final NormalizedTraceCounters counters;
        private final List<String> diagnostics;
        private final Map<String, Object> inputs;
        private final Map<String, Object> outputs;

        private TraceCase(Builder builder) {
            this.caseId = builder.caseId;
            this.phase = builder.phase;
            this.status = builder.status;
            this.entryStatus = builder.entryStatus;
            this.entryAddress = builder.entryAddress;
            this.returnValue = builder.returnValue;
            this.counters = builder.counters == null ? new NormalizedTraceCounters() : builder.counters;
            this.diagnostics = new ArrayList<>(builder.diagnostics);
            this.inputs = new LinkedHashMap<>(builder.inputs);
            this.outputs = new LinkedHashMap<>(builder.outputs);
        }

        public static Builder builder(String caseId, String phase) {
            return new Builder(caseId, phase);
        }

        private Map<String, Object> toCorpusMap(File outputDir) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("case_id", caseId);
            item.put("phase", phase);
            item.put("algorithm", "unknown");
            item.put("preset_case", phase);
            item.put("status", status);
            item.put("entry_status", entryStatus);
            item.put("entry_address", entryAddress);
            item.put("inputs", inputs);
            Map<String, Object> outputMap = new LinkedHashMap<>(outputs);
            outputMap.put("return_value", returnValue);
            item.put("outputs", outputMap);
            item.put("trace_files", traceFiles(outputDir));
            item.put("summary", summaryMap());
            item.put("diagnostics", diagnostics);
            return item;
        }

        private List<Map<String, Object>> traceFiles(File outputDir) {
            List<Map<String, Object>> out = new ArrayList<>();
            File jsonl = new File(outputDir, "events." + caseId + ".000.jsonl");
            if (jsonl.isFile()) {
                out.add(mapOf(
                        "path", jsonl.getName(),
                        "format", "jsonl",
                        "event_schema", "trace_event.v0.1",
                        "status", counters.events > 0 ? "collected" : "empty",
                        "compression", "none"));
            }
            for (String binaryName : binaryTraceFileNames(outputDir, caseId)) {
                out.add(mapOf(
                        "path", binaryName,
                        "format", BinaryTraceWriter.FORMAT,
                        "event_schema", "trace_event_binary.v0.2",
                        "status", counters.events > 0 ? "collected" : "empty",
                        "compression", "none"));
            }
            return out;
        }

        private List<Map<String, Object>> artifacts(File outputDir) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Map<String, Object> file : traceFiles(outputDir)) {
                out.add(mapOf("name", "trace_events", "path", file.get("path"), "kind", file.get("format")));
            }
            File session = new File(outputDir, "normalized_trace_session." + caseId + ".json");
            if (session.isFile()) {
                out.add(mapOf("name", "normalized_trace_session", "path", session.getName(), "kind", "json"));
            }
            File meta = new File(outputDir, "trace." + caseId + ".meta.json");
            if (meta.isFile()) {
                out.add(mapOf("name", "binary_trace_metadata", "path", meta.getName(), "kind", "json"));
            }
            return out;
        }

        private Map<String, Object> summaryMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("schema_version", "0.1");
            out.put("kind", "trace_case_summary");
            out.put("status", status);
            out.put("events", counters.events);
            out.put("instructions", counters.instructions);
            out.put("basic_blocks", 0);
            out.put("branches", counters.branches);
            out.put("memory_reads", counters.memoryReads);
            out.put("memory_writes", counters.memoryWrites);
            out.put("register_writes", counters.registerWrites);
            out.put("malformed_lines", 0);
            out.put("missing_chunks", 0);
            out.put("unsupported_chunks", 0);
            out.put("dropped_events", counters.droppedEvents);
            return out;
        }

        public static final class Builder {
            private final String caseId;
            private final String phase;
            private String status = "unknown";
            private String entryStatus = "not_requested";
            private String entryAddress;
            private String returnValue;
            private NormalizedTraceCounters counters;
            private final List<String> diagnostics = new ArrayList<>();
            private final Map<String, Object> inputs = new LinkedHashMap<>();
            private final Map<String, Object> outputs = new LinkedHashMap<>();

            private Builder(String caseId, String phase) {
                this.caseId = caseId;
                this.phase = phase;
            }

            public Builder status(String status) {
                this.status = status;
                return this;
            }

            public Builder entry(String status, String address) {
                this.entryStatus = status;
                this.entryAddress = address;
                return this;
            }

            public Builder returnValue(String returnValue) {
                this.returnValue = returnValue;
                return this;
            }

            public Builder session(NormalizedTraceSession session) {
                if (session != null) {
                    this.counters = session.getCounters();
                    this.diagnostics.addAll(session.getDiagnostics());
                }
                return this;
            }

            public Builder input(String key, Object value) {
                inputs.put(key, value);
                return this;
            }

            public Builder output(String key, Object value) {
                outputs.put(key, value);
                return this;
            }

            public Builder diagnostic(String diagnostic) {
                if (diagnostic != null && !diagnostic.isEmpty()) {
                    diagnostics.add(diagnostic);
                }
                return this;
            }

            public TraceCase build() {
                return new TraceCase(this);
            }
        }
    }
}
