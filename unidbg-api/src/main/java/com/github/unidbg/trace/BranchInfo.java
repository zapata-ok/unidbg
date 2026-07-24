package com.github.unidbg.trace;

import java.util.Collections;
import java.util.List;

final class BranchInfo {

    final boolean taken;
    final String target;
    final String fallthrough;
    final List<String> conditionRegisters;

    BranchInfo(boolean taken, String target, String fallthrough, List<String> conditionRegisters) {
        this.taken = taken;
        this.target = target;
        this.fallthrough = fallthrough;
        this.conditionRegisters = conditionRegisters == null ? Collections.<String>emptyList() : conditionRegisters;
    }
}
