#script for https://www.youtube.com/watch?v=FvH7b_qLmbU
# @author kth
# @category mygscripts
try:
	from ghidra.ghidra_builtins import (
		createDWord,
		currentAddress,
		currentProgram,
		getBytes,
	)
except ImportError:
	pass
import struct
from  ghidra.program.model.symbol import *

xrefs = currentProgram().getReferenceManager()

startAddr = currentAddress()
currAddr = currentAddress()

while True:
	createDWord(currAddr)
	data = getBytes(currAddr, 4)
	v = struct.unpack("<i", data)[0]
	if v == 0:
		break
	dest = startAddr.addWrap(v)
	xrefs.addMemoryReference(currAddr, dest, RefType.DATA, SourceType.USER_DEFINED, 0)
	currAddr = currAddr.add(4)