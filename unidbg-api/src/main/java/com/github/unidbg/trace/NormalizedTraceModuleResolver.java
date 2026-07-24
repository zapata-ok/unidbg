package com.github.unidbg.trace;

import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.Emulator;

import java.util.HashMap;
import java.util.Map;

final class NormalizedTraceModuleResolver {

    private final Emulator<?> emulator;
    private Module module;
    private final String moduleName;
    private final Map<Long, ModuleFields> cache = new HashMap<>();

    NormalizedTraceModuleResolver(Module module) {
        this.module = module;
        this.moduleName = module == null ? null : module.name;
        this.emulator = null;
    }

    NormalizedTraceModuleResolver(Emulator<?> emulator, Module module, String moduleName) {
        this.emulator = emulator;
        this.module = module;
        this.moduleName = moduleName != null ? moduleName : (module == null ? null : module.name);
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

    ModuleFields moduleFields(long address) {
        ModuleFields fields = cache.get(address);
        if (fields == null) {
            fields = resolve(address);
            cache.put(address, fields);
        }
        return fields;
    }

    boolean contains(long address) {
        Module resolved = currentModule();
        return resolved != null && address >= resolved.base && address < resolved.base + resolved.size;
    }

    private ModuleFields resolve(long address) {
        Module resolved = currentModule();
        if (resolved == null) {
            return ModuleFields.EMPTY;
        }
        if (address < resolved.base || address >= resolved.base + resolved.size) {
            return ModuleFields.EMPTY;
        }
        long offset = address - resolved.base;
        int fileOffset = resolved.virtualMemoryAddressToFileOffset(offset);
        String symbolName = null;
        try {
            Symbol symbol = resolved.findClosestSymbolByAddress(address, true);
            if (symbol != null) {
                symbolName = symbol.getName();
            }
        } catch (RuntimeException ignored) {
            // Symbol lookup is best effort and must not affect trace collection.
        }
        return new ModuleFields(resolved.name, hex(fileOffset >= 0 ? fileOffset : offset), symbolName);
    }

    private Module currentModule() {
        if (module == null && emulator != null && moduleName != null) {
            module = emulator.getMemory().findModule(moduleName);
        }
        return module;
    }

    static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }

}
