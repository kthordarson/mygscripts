# List every bitwise AND operation in the program, grouped by function
# @author kth
# @category mygscripts

try:
    from ghidra.ghidra_builtins import (
        currentProgram,
        getFunctionContaining,
    )
except ImportError:
    pass
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.database.code import InstructionDB
from ghidra.program.model.symbol import RefType, SourceType, MemReferenceImpl
from collections import defaultdict
import struct
import re

funcs_to_opaddrs = defaultdict(list)
listing = currentProgram.getListing()
instructions = listing.getInstructions(True)
for instr in instructions:
    raw_ops = list(instr.getPcode())
    for op in raw_ops:
        if op.opcode == PcodeOpAST.INT_AND:
            addr = op.seqnum.target
            func = getFunctionContaining(addr)
            funcs_to_opaddrs[func].append(addr)

for func, addrs in funcs_to_opaddrs.items():
    print(func)
    for addr in addrs:
        print(addr)
    print("")
