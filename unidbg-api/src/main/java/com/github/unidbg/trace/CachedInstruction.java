package com.github.unidbg.trace;

import capstone.api.Instruction;

import java.util.List;

final class CachedInstruction {

    final long address;
    final int size;
    final String bytesHex;
    final String mnemonic;
    final List<String> operands;
    final BranchInfo branch;
    final Instruction rawInstruction;

    CachedInstruction(long address, int size, String bytesHex, String mnemonic, List<String> operands, BranchInfo branch, Instruction rawInstruction) {
        this.address = address;
        this.size = size;
        this.bytesHex = bytesHex;
        this.mnemonic = mnemonic;
        this.operands = operands;
        this.branch = branch;
        this.rawInstruction = rawInstruction;
    }
}
