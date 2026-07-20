package com.github.unidbg.trace;

import com.github.unidbg.Module;
import com.github.unidbg.Symbol;

import java.util.Map;

final class NormalizedTraceModuleResolver {

    private final Module module;

    NormalizedTraceModuleResolver(Module module) {
        this.module = module;
    }

    void putModuleFields(Map<String, Object> event, long address) {
        if (module == null) {
            event.put("module", null);
            event.put("file_offset", null);
            return;
        }
        if (address < module.base || address >= module.base + module.size) {
            event.put("module", null);
            event.put("file_offset", null);
            return;
        }
        event.put("module", module.name);
        long offset = address - module.base;
        int fileOffset = module.virtualMemoryAddressToFileOffset(offset);
        event.put("file_offset", hex(fileOffset >= 0 ? fileOffset : offset));
        try {
            Symbol symbol = module.findClosestSymbolByAddress(address, true);
            if (symbol != null) {
                event.put("symbol", symbol.getName());
            }
        } catch (RuntimeException ignored) {
            // Symbol lookup is best effort and must not affect trace collection.
        }
    }

    static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }
}
