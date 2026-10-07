# Create functions from a pointer table with validation (safe version)
# original author: ReverseEngineer
# @author kth
# @category mygscripts
# @menupath Tools.Create Functions From Pointer Table (Safe)

try:
	from ghidra.ghidra_builtins import (
		createFunction,
		currentProgram,
		disassemble,
		toAddr,
	)
except ImportError:
	pass
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()

start = toAddr(0x004090a8)
end   = toAddr(0x004090b8)

addr = start
ptr_size = currentProgram.getDefaultPointerSize()

while addr <= end:
	data = listing.getDataAt(addr)

	if data and data.isPointer():
		entry = data.getValue()
		target = data.getValue()
		# Validate memory
		if not mem.contains(entry):
			addr = addr.add(ptr_size)
			continue

		# Skip if function already exists
		if fm.getFunctionAt(entry):
			addr = addr.add(ptr_size)
			continue

		# Force disassembly at entry
		if not listing.getInstructionAt(entry):
			disassemble(entry)

		# If inside another function, skip
		if fm.getFunctionContaining(entry):
			addr = addr.add(ptr_size)
			continue

		try:
			if mem.contains(target):
				if not fm.getFunctionAt(target):
					#Let Ghidra infer body automatically
					fn = createFunction(target, None)
					if fn:
						fn.setName("handler_%X" % target.getOffset(), SourceType.USER_DEFINED)
						# fm.createFunction("handler_%X" % entry.getOffset(), entry, None, SourceType.USER_DEFINED)
						print("Created function at", entry)
		except Exception as e:
			print("Failed at", entry, ":", e)

	addr = addr.add(ptr_size)