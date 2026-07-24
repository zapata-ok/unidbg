package com.github.unidbg.trace;

import com.alibaba.fastjson.JSON;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

final class BinaryTraceWriter implements Closeable {

    static final String FORMAT = "zapata-trace-bin-v0.1";
    private static final int MAGIC = 0x5a545243; // ZTRC
    private static final byte EVENT_INSTRUCTION = 1;
    private static final byte EVENT_MEMORY_READ = 2;
    private static final byte EVENT_MEMORY_WRITE = 3;

    private final NormalizedTraceConfig config;
    private final File eventFile;
    private final DataOutputStream out;
    private long events;
    private long instructions;
    private long branches;
    private long memoryReads;
    private long memoryWrites;
    private long registerWrites;
    private boolean closed;

    BinaryTraceWriter(NormalizedTraceConfig config) throws IOException {
        this.config = config;
        this.eventFile = new File(config.outputDir, "trace." + config.caseId + ".000.bin");
        this.out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(eventFile), 1024 * 1024));
        out.writeInt(MAGIC);
        out.writeShort(1);
        writeString(config.backendName);
        writeString(config.caseId);
    }

    String eventFileName() {
        return eventFile.getName();
    }

    void writeInstruction(long seq, PendingInstruction instruction, NormalizedTraceRegisters.Snapshot afterRegisters) throws IOException {
        if (closed) return;
        out.writeByte(EVENT_INSTRUCTION);
        out.writeLong(seq);
        out.writeLong(instruction.pc);
        writeModuleFields(instruction.moduleFields);
        writeString(instruction.instruction.bytesHex);
        writeString(instruction.instruction.mnemonic);
        out.writeShort(instruction.instruction.operands.size());
        for (String operand : instruction.instruction.operands) writeString(operand);
        if (instruction.instruction.branch == null) {
            out.writeBoolean(false);
        } else {
            out.writeBoolean(true);
            out.writeBoolean(instruction.instruction.branch.taken);
            writeString(instruction.instruction.branch.target);
            writeString(instruction.instruction.branch.fallthrough);
        }
        writeRegisterWrites(instruction.beforeRegisters, afterRegisters);
        out.writeShort(instruction.memoryAccesses.size());
        for (MemoryAccess access : instruction.memoryAccesses) writeMemoryAccess(access);
        events++;
        instructions++;
        if (instruction.instruction.branch != null) branches++;
        registerWrites += countRegisterWrites(instruction.beforeRegisters, afterRegisters);
    }

    void writeMemoryEvent(long seq, String kind, ModuleFields moduleFields, long pc, MemoryAccess access) throws IOException {
        if (closed) return;
        out.writeByte("memory_write".equals(kind) ? EVENT_MEMORY_WRITE : EVENT_MEMORY_READ);
        out.writeLong(seq);
        out.writeLong(pc);
        writeModuleFields(moduleFields == null ? ModuleFields.EMPTY : moduleFields);
        writeMemoryAccess(access);
        events++;
        if ("memory_write".equals(kind)) memoryWrites++; else memoryReads++;
    }

    void recordMemoryAccess(String access) {
        if ("write".equals(access)) memoryWrites++; else if ("read".equals(access)) memoryReads++;
    }

    void writeMetadata() throws IOException {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "0.1");
        meta.put("kind", "binary_trace_metadata");
        meta.put("format", FORMAT);
        meta.put("case_id", config.caseId);
        meta.put("path", eventFileName());
        meta.put("events", events);
        meta.put("instructions", instructions);
        meta.put("branches", branches);
        meta.put("memory_reads", memoryReads);
        meta.put("memory_writes", memoryWrites);
        meta.put("register_writes", registerWrites);
        File metaFile = new File(config.outputDir, "trace." + config.caseId + ".meta.json");
        try (java.io.BufferedWriter writer = new java.io.BufferedWriter(new java.io.FileWriter(metaFile))) {
            writer.write(JSON.toJSONString(meta, true));
            writer.newLine();
        }
    }

    private void writeModuleFields(ModuleFields fields) throws IOException {
        writeString(fields.moduleName);
        writeString(fields.fileOffset);
        writeString(fields.symbol);
    }

    private void writeRegisterWrites(NormalizedTraceRegisters.Snapshot before, NormalizedTraceRegisters.Snapshot after) throws IOException {
        int count = 0;
        if (before != null && after != null) {
            int len = Math.min(before.names.length, after.names.length);
            for (int i = 0; i < len; i++) if (before.valid[i] && after.valid[i] && before.values[i] != after.values[i]) count++;
            out.writeShort(count);
            for (int i = 0; i < len; i++) {
                if (before.valid[i] && after.valid[i] && before.values[i] != after.values[i]) {
                    writeString(after.names[i]);
                    out.writeLong(after.values[i]);
                }
            }
        } else {
            out.writeShort(0);
        }
    }

    private int countRegisterWrites(NormalizedTraceRegisters.Snapshot before, NormalizedTraceRegisters.Snapshot after) {
        if (before == null || after == null) return 0;
        int count = 0;
        int len = Math.min(before.names.length, after.names.length);
        for (int i = 0; i < len; i++) if (before.valid[i] && after.valid[i] && before.values[i] != after.values[i]) count++;
        return count;
    }

    private void writeMemoryAccess(MemoryAccess access) throws IOException {
        out.writeByte("write".equals(access.access) ? 2 : 1);
        out.writeLong(access.address);
        out.writeInt(access.size);
        if (access.valueHex == null) {
            out.writeShort(-1);
        } else {
            byte[] bytes = hexToBytes(access.valueHex);
            out.writeShort(bytes.length);
            out.write(bytes);
        }
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    private void writeString(String value) throws IOException {
        if (value == null) {
            out.writeInt(-1);
            return;
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        out.flush();
        out.close();
    }
}
