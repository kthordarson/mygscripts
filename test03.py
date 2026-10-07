# Test: walk instructions from a fixed address and print references
#armageddon
# @author kth
# @category mygscripts
try:
	from ghidra.ghidra_builtins import (
		currentProgram,
		toAddr,
	)
except ImportError:
	pass
from ghidra.program.model.listing import CodeUnitFormat, CodeUnitFormatOptions
from ghidra.program.model.symbol import RefType
codeUnitFormat = CodeUnitFormat(CodeUnitFormatOptions(CodeUnitFormatOptions.ShowBlockName.ALWAYS,CodeUnitFormatOptions.ShowNamespace.ALWAYS,"",True,True,True,True,True,True,True))
addr = toAddr('0040dfe0')

limiter = 0
limit = 50
instruction = currentProgram().getListing().getInstructionAt(addr)
while True:
	t = instruction.getFlowType()
	if t == RefType.UNCONDITIONAL_JUMP:
		dest_addr = toAddr(int(str(instruction)[2:],16))
		sym = currentProgram().symbolTable.getPrimarySymbol(dest_addr)
		if 'LAB_' in str(sym):
			addr = dest_addr
			instruction = currentProgram().getListing().getInstructionAt(addr)
			continue
	print(str(instruction.address) +': '+codeUnitFormat.getRepresentationString(instruction))
	instruction = instruction.getNext()
	limiter += 1
	if limiter > limit:
		break