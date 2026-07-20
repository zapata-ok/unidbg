package com.github.unidbg.trace;

public final class AddressRange {

    public final long begin;
    public final long end;

    public AddressRange(long begin, long end) {
        this.begin = begin;
        this.end = end;
    }

    public boolean contains(long address) {
        return begin > end || (address >= begin && address <= end);
    }
}
