# Test: walk instructions from current address and print references
#exceptional
# @author kth
# @category mygscripts
try:
	from ghidra.ghidra_builtins import (
		currentAddress,
		currentProgram,
		toAddr,
	)
except ImportError:
	pass
from ghidra.program.model.listing import CodeUnitFormat, CodeUnitFormatOptions
from ghidra.program.model.symbol import RefType
codeUnitFormat = CodeUnitFormat(CodeUnitFormatOptions(CodeUnitFormatOptions.ShowBlockName.ALWAYS,CodeUnitFormatOptions.ShowNamespace.ALWAYS,"",True,True,True,True,True,True,True))
addr = currentAddress() #toAddr('<start_address>')

limiter = 0
instruction = currentProgram().getListing().getInstructionAt(addr)
while True:
	t = instruction.getFlowType()
	if t == RefType.UNCONDITIONAL_CALL:
		dest_addr = toAddr(int(str(instruction)[7:],16))
		sym = currentProgram().symbolTable.getPrimarySymbol(dest_addr)
		if 'FUN_' in str(sym):
			addr = dest_addr
			instruction = currentProgram().getListing().getInstructionAt(addr)
			continue
	print(codeUnitFormat.getRepresentationString(instruction))
	instruction = instruction.getNext()
	limiter += 1
	if limiter > 50:
		break
	