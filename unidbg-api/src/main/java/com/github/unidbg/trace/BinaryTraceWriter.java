package com.github.unidbg.trace;

import com.alibaba.fastjson.JSON;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.CheckedOutputStream;

final class BinaryTraceWriter implements Closeable {

    static final String FORMAT = "zapata-trace-bin-v0.2";
    private static final int MAGIC = 0x5a545243; // ZTRC
    private static final int VERSION = 2;
    private static final int EVENT_INSTRUCTION = 1;
    private static final int EVENT_MEMORY_READ = 2;
    private static final int EVENT_MEMORY_WRITE = 3;
    private static final long NULL_ID = 0xffff_ffffL;
    private static final int HEADER_SIZE = 4 + 2 + 2 + 4 + 10 * 8 + 4 + 4;

    private final NormalizedTraceConfig config;
    private final File outputDir;
    private final List<Chunk> chunks = new ArrayList<>();
    private final Map<String, Integer> registerIds = new LinkedHashMap<>();
    private final List<String> registerNames = new ArrayList<>();
    private final int maxEventsPerChunk;
    private final long maxChunkBytes;
    private long events;
    private long instructions;
    private long branches;
    private long memoryReads;
    private long memoryWrites;
    private long registerWrites;
    private boolean closed;
    private Chunk currentChunk;

    BinaryTraceWriter(NormalizedTraceConfig config) throws IOException {
        this.config = config;
        this.outputDir = config.outputDir;
        this.maxEventsPerChunk = config.maxEvents > 0 ? (int) Math.min(Integer.MAX_VALUE, config.maxEvents) : Integer.MAX_VALUE;
        this.maxChunkBytes = config.maxEventFileBytes > 0 ? config.maxEventFileBytes : 0L;
        for (int i = 0; i < config.selectedRegisterNames.length; i++) {
            registerIds.put(config.selectedRegisterNames[i], i + 1);
            registerNames.add(config.selectedRegisterNames[i]);
        }
        rotateChunk();
    }

    String eventFileName() {
        return chunks.isEmpty() ? fileNameForChunk(0) : chunks.get(0).file.getName();
    }

    List<String> eventFileNames() {
        List<String> names = new ArrayList<>(chunks.size());
        for (Chunk chunk : chunks) {
            names.add(chunk.file.getName());
        }
        return Collections.unmodifiableList(names);
    }

    void writeInstruction(long seq, PendingInstruction instruction, NormalizedTraceRegisters.Snapshot afterRegisters) throws IOException {
        if (closed) return;
        long estimatedEventBytes = estimateInstructionBytes(instruction, afterRegisters);
        ensureChunkForInstruction(estimatedEventBytes);
        Chunk chunk = currentChunk;
        chunk.startEvent();

        long moduleId = chunk.internModule(instruction.moduleFields.moduleName);
        long symbolId = chunk.internStringId(instruction.moduleFields.symbol);
        long bytesId = chunk.internStringId(config.includeInstructionBytes ? instruction.instruction.bytesHex : "");
        long mnemonicId = chunk.internStringId(instruction.instruction.mnemonic);
        List<Integer> operandIds = new ArrayList<>(instruction.instruction.operands.size());
        for (String operand : instruction.instruction.operands) {
            operandIds.add(chunk.internString(operand));
        }

        chunk.out.writeByte(EVENT_INSTRUCTION);
        chunk.out.writeLong(seq);
        chunk.out.writeLong(instruction.pc);
        writeVarUInt(chunk, moduleId);
        chunk.out.writeLong(parseHexOrZero(instruction.moduleFields.fileOffset));
        writeVarUInt(chunk, symbolId);
        writeVarUInt(chunk, bytesId);
        writeVarUInt(chunk, mnemonicId);
        writeVarUInt(chunk, operandIds.size());
        for (Integer operandId : operandIds) {
            writeVarUInt(chunk, operandId);
        }
        if (instruction.instruction.branch == null) {
            chunk.out.writeByte(0);
        } else {
            chunk.out.writeByte(1);
            chunk.out.writeByte(instruction.instruction.branch.taken ? 1 : 0);
            writeVarUInt(chunk, chunk.internStringId(instruction.instruction.branch.target));
            writeVarUInt(chunk, chunk.internStringId(instruction.instruction.branch.fallthrough));
        }

        int registerWriteCount = writeRegisterWrites(chunk, instruction.beforeRegisters, afterRegisters);
        writeVarUInt(chunk, instruction.memoryAccesses.size());
        for (MemoryAccess access : instruction.memoryAccesses) {
            writeMemoryAccess(chunk, access);
        }

        chunk.finishEvent();
        events++;
        instructions++;
        chunk.instructions++;
        if (instruction.instruction.branch != null) {
            branches++;
        }
        registerWrites += registerWriteCount;
        chunk.registerWrites += registerWriteCount;
        for (MemoryAccess access : instruction.memoryAccesses) {
            if ("write".equals(access.access)) {
                memoryWrites++;
                chunk.memoryWrites++;
            } else {
                memoryReads++;
                chunk.memoryReads++;
            }
        }
        chunk.estimatedBytes += estimatedEventBytes;
    }

    void writeMemoryEvent(long seq, String kind, ModuleFields moduleFields, long pc, MemoryAccess access) throws IOException {
        if (closed) return;
        long estimatedEventBytes = estimateMemoryBytes(access);
        ensureChunkForMemory(estimatedEventBytes);
        Chunk chunk = currentChunk;
        chunk.startEvent();

        long moduleId = chunk.internModule(moduleFields == null ? null : moduleFields.moduleName);
        long symbolId = chunk.internStringId(moduleFields == null ? null : moduleFields.symbol);
        chunk.out.writeByte("memory_write".equals(kind) ? EVENT_MEMORY_WRITE : EVENT_MEMORY_READ);
        chunk.out.writeLong(seq);
        chunk.out.writeLong(pc);
        writeVarUInt(chunk, moduleId);
        chunk.out.writeLong(parseHexOrZero(moduleFields == null ? null : moduleFields.fileOffset));
        writeVarUInt(chunk, symbolId);
        writeMemoryAccess(chunk, access);

        chunk.finishEvent();
        events++;
        if ("memory_write".equals(kind)) {
            memoryWrites++;
            chunk.memoryWrites++;
        } else {
            memoryReads++;
            chunk.memoryReads++;
        }
        chunk.estimatedBytes += estimatedEventBytes;
    }

    void recordMemoryAccess(String access) {
        // counters are updated in the event writers; keep this for compatibility with legacy JSONL-only paths.
    }

    void writeMetadata() throws IOException {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "0.2");
        meta.put("kind", "binary_trace_metadata");
        meta.put("format", FORMAT);
        meta.put("case_id", config.caseId);
        meta.put("chunks", chunkSummaries());
        meta.put("events", events);
        meta.put("instructions", instructions);
        meta.put("branches", branches);
        meta.put("memory_reads", memoryReads);
        meta.put("memory_writes", memoryWrites);
        meta.put("register_writes", registerWrites);
        long stringCount = 0;
        long moduleCount = 0;
        for (Chunk chunk : chunks) {
            stringCount += chunk.strings.size();
            moduleCount += chunk.modules.size();
        }
        meta.put("strings", stringCount);
        meta.put("modules", moduleCount);
        meta.put("registers", registerNames.size());
        File metaFile = new File(outputDir, "trace." + config.caseId + ".meta.json");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(metaFile))) {
            writer.write(JSON.toJSONString(meta, true));
            writer.newLine();
        }
    }

    private List<Map<String, Object>> chunkSummaries() {
        List<Map<String, Object>> summaries = new ArrayList<>(chunks.size());
        for (Chunk chunk : chunks) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("path", chunk.file.getName());
            item.put("format", FORMAT);
            item.put("event_schema", "trace_event_binary.v0.2");
            item.put("status", "collected");
            item.put("compression", "none");
            item.put("events", chunk.events);
            item.put("bytes", chunk.bytesWritten);
            item.put("checksum", Long.toUnsignedString(chunk.crc32.getValue()));
            summaries.add(item);
        }
        return summaries;
    }

    private void ensureChunkForInstruction(long estimatedEventBytes) throws IOException {
        if (currentChunk == null) {
            rotateChunk();
            return;
        }
        if (currentChunk.events >= maxEventsPerChunk) {
            rotateChunk();
            return;
        }
        if (maxChunkBytes > 0 && currentChunk.estimatedBytes + estimatedEventBytes > maxChunkBytes) {
            rotateChunk();
        }
    }

    private void ensureChunkForMemory(long estimatedEventBytes) throws IOException {
        if (currentChunk == null) {
            rotateChunk();
            return;
        }
        if (currentChunk.events >= maxEventsPerChunk) {
            rotateChunk();
            return;
        }
        if (maxChunkBytes > 0 && currentChunk.estimatedBytes + estimatedEventBytes > maxChunkBytes) {
            rotateChunk();
        }
    }

    private void rotateChunk() throws IOException {
        closeCurrentChunk();
        Chunk chunk = new Chunk(chunks.size());
        chunks.add(chunk);
        currentChunk = chunk;
    }

    private void closeCurrentChunk() throws IOException {
        if (currentChunk != null) {
            currentChunk.close();
        }
    }

    private int writeRegisterWrites(Chunk chunk, NormalizedTraceRegisters.Snapshot before, NormalizedTraceRegisters.Snapshot after) throws IOException {
        if (before == null || after == null) {
            writeVarUInt(chunk, 0);
            return 0;
        }
        int len = Math.min(before.names.length, after.names.length);
        int count = 0;
        for (int i = 0; i < len; i++) {
            if (before.valid[i] && after.valid[i] && before.values[i] != after.values[i]) {
                count++;
            }
        }
        writeVarUInt(chunk, count);
        for (int i = 0; i < len; i++) {
            if (!before.valid[i] || !after.valid[i] || before.values[i] == after.values[i]) {
                continue;
            }
            int regId = registerIds.getOrDefault(after.names[i], 0);
            writeVarUInt(chunk, regId);
            chunk.out.writeLong(after.values[i]);
        }
        return count;
    }

    private int countRegisterWrites(NormalizedTraceRegisters.Snapshot before, NormalizedTraceRegisters.Snapshot after) {
        if (before == null || after == null) {
            return 0;
        }
        int len = Math.min(before.names.length, after.names.length);
        int count = 0;
        for (int i = 0; i < len; i++) {
            if (before.valid[i] && after.valid[i] && before.values[i] != after.values[i]) {
                count++;
            }
        }
        return count;
    }

    private void writeMemoryAccess(Chunk chunk, MemoryAccess access) throws IOException {
        chunk.out.writeByte("write".equals(access.access) ? 2 : 1);
        chunk.out.writeLong(access.address);
        writeVarUInt(chunk, access.size);
        if (access.valueHex == null) {
            writeVarUInt(chunk, 0);
        } else {
            byte[] bytes = hexToBytes(access.valueHex);
            writeVarUInt(chunk, bytes.length + 1L);
            chunk.out.write(bytes);
        }
    }

    private void writeVarUInt(Chunk chunk, long value) throws IOException {
        while ((value & ~0x7fL) != 0) {
            chunk.out.writeByte((int) ((value & 0x7fL) | 0x80L));
            value >>>= 7;
        }
        chunk.out.writeByte((int) value);
    }

    private long estimateInstructionBytes(PendingInstruction instruction, NormalizedTraceRegisters.Snapshot afterRegisters) {
        long bytes = 1 + 8 + 8 + 2 + 8 + 2 + 2 + 2 + 1;
        bytes += 2L * instruction.instruction.operands.size();
        bytes += 1;
        if (instruction.instruction.branch != null) {
            bytes += 1 + 2 + 2;
        }
        if (beforeHasRegisters(instruction.beforeRegisters, afterRegisters)) {
            bytes += 9L * countRegisterWrites(instruction.beforeRegisters, afterRegisters);
        }
        bytes += 1;
        for (MemoryAccess access : instruction.memoryAccesses) {
            bytes += estimateMemoryBytes(access);
        }
        return bytes;
    }

    private long estimateMemoryBytes(MemoryAccess access) {
        return 1 + 8 + 2 + 1 + (access.valueHex == null ? 0 : access.valueHex.length() / 2);
    }

    private boolean beforeHasRegisters(NormalizedTraceRegisters.Snapshot before, NormalizedTraceRegisters.Snapshot after) {
        return before != null && after != null;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static long parseHexOrZero(String value) {
        if (value == null || value.isEmpty()) {
            return 0L;
        }
        String normalized = value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;
        return Long.parseUnsignedLong(normalized, 16);
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        closeCurrentChunk();
    }

    private final class Chunk implements Closeable {
        private final File file;
        private final RandomAccessFile raf;
        private final CheckedOutputStream checkedOut;
        private final CountingOutputStream countingOut;
        private final BufferedOutputStream bufferedOut;
        private final java.io.DataOutputStream out;
        private final CRC32 crc32 = new CRC32();
        private final Map<String, Integer> stringIds = new LinkedHashMap<>();
        private final Map<String, Integer> moduleIds = new LinkedHashMap<>();
        private final List<String> strings = new ArrayList<>();
        private final List<ModuleRecord> modules = new ArrayList<>();
        private long eventDataOffset;
        private long stringTableOffset;
        private long moduleTableOffset;
        private long registerTableOffset;
        private long events;
        private long instructions;
        private long memoryReads;
        private long memoryWrites;
        private long registerWrites;
        private long bytesWritten;
        private long estimatedBytes = HEADER_SIZE;
        private boolean closed;

        private Chunk(int index) throws IOException {
            this.file = new File(outputDir, fileNameForChunk(index));
            this.raf = new RandomAccessFile(file, "rw");
            this.raf.setLength(0);
            this.checkedOut = new CheckedOutputStream(new FileOutputStream(raf.getFD()), crc32);
            this.countingOut = new CountingOutputStream(checkedOut);
            this.bufferedOut = new BufferedOutputStream(countingOut, 1024 * 1024);
            this.out = new java.io.DataOutputStream(bufferedOut);
            writeHeaderPlaceholder();
            this.eventDataOffset = HEADER_SIZE;
        }

        private void writeHeaderPlaceholder() throws IOException {
            out.writeInt(MAGIC);
            out.writeShort(VERSION);
            out.writeShort(0);
            out.writeInt(chunks.size());
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeLong(0L);
            out.writeInt(0);
            out.writeInt(0);
        }

        private long bytesWritten() throws IOException {
            out.flush();
            return countingOut.bytesWritten;
        }

        private long internStringId(String value) {
            if (value == null) {
                return NULL_ID;
            }
            return internString(value);
        }

        private int internString(String value) {
            if (value == null) {
                return -1;
            }
            Integer id = stringIds.get(value);
            if (id != null) {
                return id;
            }
            int nextId = strings.size() + 1;
            stringIds.put(value, nextId);
            strings.add(value);
            return nextId;
        }

        private long internModule(String moduleName) {
            if (moduleName == null) {
                return NULL_ID;
            }
            Integer id = moduleIds.get(moduleName);
            if (id != null) {
                return id;
            }
            int nextId = modules.size() + 1;
            moduleIds.put(moduleName, nextId);
            modules.add(new ModuleRecord(nextId, moduleName));
            internString(moduleName);
            return nextId;
        }

        private void startEvent() {
        }

        private void finishEvent() {
            events++;
        }

        @Override
        public void close() throws IOException {
            if (closed) return;
            closed = true;
            writeTables();
            out.flush();
            bufferedOut.flush();
            bytesWritten = countingOut.bytesWritten;
            patchHeader();
            checkedOut.close();
            raf.close();
        }

        private void writeTables() throws IOException {
            for (String registerName : registerNames) {
                internString(registerName);
            }
            stringTableOffset = bytesWritten();
            out.writeInt(strings.size());
            for (int i = 0; i < strings.size(); i++) {
                byte[] bytes = strings.get(i).getBytes(StandardCharsets.UTF_8);
                out.writeInt(i + 1);
                out.writeInt(bytes.length);
                out.write(bytes);
            }
            moduleTableOffset = bytesWritten();
            out.writeInt(modules.size());
            for (ModuleRecord module : modules) {
                out.writeInt(module.id);
                out.writeLong(0L);
                out.writeInt(internString(module.name));
            }
            registerTableOffset = bytesWritten();
            out.writeInt(registerNames.size());
            for (int i = 0; i < registerNames.size(); i++) {
                out.writeInt(i + 1);
                out.writeInt(internString(registerNames.get(i)));
            }
        }

        private void patchHeader() throws IOException {
            raf.seek(0L);
            raf.writeInt(MAGIC);
            raf.writeShort(VERSION);
            raf.writeShort(0);
            raf.writeInt(chunks.indexOf(this));
            raf.writeLong(events);
            raf.writeLong(this.instructions);
            raf.writeLong(this.memoryReads);
            raf.writeLong(this.memoryWrites);
            raf.writeLong(this.registerWrites);
            raf.writeLong(eventDataOffset);
            raf.writeLong(stringTableOffset);
            raf.writeLong(moduleTableOffset);
            raf.writeLong(registerTableOffset);
            raf.writeLong(bytesWritten);
            raf.writeInt((int) crc32.getValue());
            raf.writeInt(0);
        }
    }

    private String fileNameForChunk(int index) {
        return String.format("trace.%s.%03d.bin", config.caseId, index);
    }

    private static final class CountingOutputStream extends OutputStream {
        private final OutputStream delegate;
        private long bytesWritten;

        private CountingOutputStream(OutputStream delegate) {
            this.delegate = delegate;
        }

        @Override
        public void write(int b) throws IOException {
            delegate.write(b);
            bytesWritten++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            delegate.write(b, off, len);
            bytesWritten += len;
        }

        @Override
        public void flush() throws IOException {
            delegate.flush();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

    private static final class ModuleRecord {
        private final int id;
        private final String name;

        private ModuleRecord(int id, String name) {
            this.id = id;
            this.name = name;
        }
    }
}
