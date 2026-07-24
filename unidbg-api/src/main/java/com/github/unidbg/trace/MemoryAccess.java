package com.github.unidbg.trace;

final class MemoryAccess {

    final String access;
    final long address;
    final int size;
    final String valueHex;

    MemoryAccess(String access, long address, int size, String valueHex) {
        this.access = access;
        this.address = address;
        this.size = size;
        this.valueHex = valueHex;
    }
}
