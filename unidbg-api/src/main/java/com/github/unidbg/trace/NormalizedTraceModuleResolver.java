package com.github.unidbg.trace;

import com.github.unidbg.Module;
import com.github.unidbg.Symbol;

import java.util.HashMap;
import java.util.Map;

final class NormalizedTraceModuleResolver {

    private final Module module;
    private final Map<Long, ModuleFields> cache = new HashMap<>();

    NormalizedTraceModuleResolver(Module module) {
        this.module = module;
    }

    void putModuleFields(Map<String, Object> event, long address) {
        ModuleFields fields = cache.get(address);
        if (fields == null) {
            fields = resolve(address);
            cache.put(address, fields);
        }
        event.put("module", fields.moduleName);
        event.put("file_offset", fields.fileOffset);
        if (fields.symbol != null) {
            event.put("symbol", fields.symbol);
        }
    }

    private ModuleFields resolve(long address) {
        if (module == null) {
            return new ModuleFields(null, null, null);
        }
        if (address < module.base || address >= module.base + module.size) {
            return new ModuleFields(null, null, null);
        }
        long offset = address - module.base;
        int fileOffset = module.virtualMemoryAddressToFileOffset(offset);
        String symbolName = null;
        try {
            Symbol symbol = module.findClosestSymbolByAddress(address, true);
            if (symbol != null) {
                symbolName = symbol.getName();
            }
        } catch (RuntimeException ignored) {
            // Symbol lookup is best effort and must not affect trace collection.
        }
        return new ModuleFields(module.name, hex(fileOffset >= 0 ? fileOffset : offset), symbolName);
    }

    static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }

    private static final class ModuleFields {
        private final String moduleName;
        private final String fileOffset;
        private final String symbol;

        private ModuleFields(String moduleName, String fileOffset, String symbol) {
            this.moduleName = moduleName;
            this.fileOffset = fileOffset;
            this.symbol = symbol;
        }
    }
}
