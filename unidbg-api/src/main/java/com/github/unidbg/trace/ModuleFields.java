package com.github.unidbg.trace;

final class ModuleFields {

    static final ModuleFields EMPTY = new ModuleFields(null, null, null);

    final String moduleName;
    final String fileOffset;
    final String symbol;

    ModuleFields(String moduleName, String fileOffset, String symbol) {
        this.moduleName = moduleName;
        this.fileOffset = fileOffset;
        this.symbol = symbol;
    }
}
