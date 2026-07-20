package com.github.unidbg.trace;

public final class NormalizedTraceCounters {

    public long events;
    public long instructions;
    public long branches;
    public long memoryReads;
    public long memoryWrites;
    public long registerWrites;
    public long droppedEvents;

    public NormalizedTraceCounters snapshot() {
        NormalizedTraceCounters copy = new NormalizedTraceCounters();
        copy.events = events;
        copy.instructions = instructions;
        copy.branches = branches;
        copy.memoryReads = memoryReads;
        copy.memoryWrites = memoryWrites;
        copy.registerWrites = registerWrites;
        copy.droppedEvents = droppedEvents;
        return copy;
    }
}
