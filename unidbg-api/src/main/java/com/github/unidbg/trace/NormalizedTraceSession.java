package com.github.unidbg.trace;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.UnHook;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class NormalizedTraceSession implements Closeable {

    private final Emulator<?> emulator;
    private final NormalizedTraceConfig config;
    private final NormalizedTraceWriter writer;
    private final List<UnHook> hooks = new ArrayList<>();
    private PendingInstruction pendingInstruction;
    private boolean closed;

    NormalizedTraceSession(Emulator<?> emulator, NormalizedTraceConfig config, NormalizedTraceWriter writer) {
        this.emulator = emulator;
        this.config = config;
        this.writer = writer;
    }

    void addHook(UnHook hook) {
        if (hook != null) {
            hooks.add(hook);
        }
    }

    Emulator<?> emulator() {
        return emulator;
    }

    NormalizedTraceConfig config() {
        return config;
    }

    NormalizedTraceWriter writer() {
        return writer;
    }

    PendingInstruction pendingInstruction() {
        return pendingInstruction;
    }

    void pendingInstruction(PendingInstruction pendingInstruction) {
        this.pendingInstruction = pendingInstruction;
    }

    boolean shouldStop() {
        return config.maxEvents > 0 && writer.counters().events >= config.maxEvents;
    }

    void stopIfNeeded() {
        if (shouldStop() && config.stopEmulatorOnMaxEvents) {
            writer.addDiagnostic("max event count reached; emulator stopped");
            emulator.getBackend().emu_stop();
        }
    }

    public NormalizedTraceCounters getCounters() {
        return writer.counters();
    }

    public List<String> getDiagnostics() {
        return writer.diagnostics();
    }

    public String getEventFileName() {
        return writer.eventFileName();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        for (UnHook hook : hooks) {
            hook.unhook();
        }
        hooks.clear();
        if (pendingInstruction != null) {
            writer.addDiagnostic("last_instruction_delta_unavailable");
            pendingInstruction.flush(writer, null);
            pendingInstruction = null;
        }
        writer.close();
        writer.writeSessionSummary("closed");
    }
}
