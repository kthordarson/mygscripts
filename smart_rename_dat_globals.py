# @category mygscripts
# @author kth
# @description Smart rename DAT_* globals using access + function context

try:
	from ghidra.ghidra_builtins import (
		askChoices,
		askDirectory,
		askFile,
		currentProgram,
		getFunctionContaining,
		getReferencesTo,
		getSymbol,
		monitor,
		setBackgroundColor,
		toAddr,
		getBytes,
		addr_space,
		addr_fact
	)
except ImportError:
	pass

from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.data import (
	ByteDataType,
	WordDataType,
	DWordDataType,
	QWordDataType,
	PointerDataType,
	ArrayDataType,
)
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import Address
from ghidra.util import Msg

program = currentProgram
listing = program.getListing()
symbolTable = program.getSymbolTable()
refManager = program.getReferenceManager()
dtm = program.getDataTypeManager()

# -----------------------------
# Helper heuristics
# -----------------------------


def guess_role_from_function(func_name):
	lname = func_name.lower()
	if "read" in lname:
		return "FileRead"
	if "write" in lname or "save" in lname:
		return "FileWrite"
	if "meter" in lname:
		return "Meter"
	if "register" in lname:
		return "Registration"
	if "plugin" in lname or "loadlibrary" in lname:
		return "Plugin"
	if "audio" in lname or "wave" in lname:
		return "Audio"
	if "dialog" in lname or "dlg" in lname:
		return "Dialog"
	return "Global"


def guess_type_from_access(access_sizes, is_pointer, is_array):
	if is_array:
		return ArrayDataType(ByteDataType(), 0x100, 1)
	if is_pointer:
		return PointerDataType(ByteDataType())
	if 8 in access_sizes:
		return QWordDataType()
	if 4 in access_sizes:
		return DWordDataType()
	if 2 in access_sizes:
		return WordDataType()
	return ByteDataType()


# -----------------------------
# Main analysis
# -----------------------------


def analyze_symbol(symbol):
	addr = symbol.getAddress()
	refs = refManager.getReferencesTo(addr)

	access_sizes = set()
	is_pointer = False
	is_array = False
	is_counter = False
	functions = set()

	for ref in refs:
		instr = listing.getInstructionAt(ref.getFromAddress())
		if not instr:
			continue

		func = listing.getFunctionContaining(instr.getAddress())
		if func:
			functions.add(func.getName())

		mnem = instr.getMnemonicString().lower()

		# Increment / counter detection
		if mnem in ("inc", "dec", "add", "sub"):
			is_counter = True

		# Pointer-like usage
		if mnem in ("lea", "push"):
			is_pointer = True

		# Array indexing
		if "[" in instr.toString():
			is_array = True

		# Operand size heuristic
		try:
			size = instr.getDefaultOperandRepresentation(0)
			if "byte" in size:
				access_sizes.add(1)
			elif "word" in size:
				access_sizes.add(2)
			elif "dword" in size:
				access_sizes.add(4)
			elif "qword" in size:
				access_sizes.add(8)
		except Exception as e:
			Msg.warn(None, "Operand size heuristic failed at %s: %s" % (instr.getAddress(), str(e)))

	role = "Global"
	if len(functions) == 1:
		role = guess_role_from_function(list(functions)[0])
	elif len(functions) > 1:
		for f in functions:
			role = guess_role_from_function(f)
			if role != "Global":
				break

	# Name construction
	suffix = addr.toString().replace("0x", "")
	if is_array:
		name = "g_%sBuffer_%s" % (role, suffix)
	elif is_counter:
		name = "g_%sCount_%s" % (role, suffix)
	elif is_pointer:
		name = "g_%sPtr_%s" % (role, suffix)
	else:
		name = "g_%sValue_%s" % (role, suffix)

	dtype = guess_type_from_access(access_sizes, is_pointer, is_array)
	return name, dtype


# -----------------------------
# Apply changes
# -----------------------------


def apply(symbol, new_name, dtype):
	addr = symbol.getAddress()
	try:
		symbol.setName(new_name, SourceType.USER_DEFINED)
	except Exception as e:
		Msg.warn(None, "Rename failed: %s error: %s" % (symbol.getName(), str(e)))

	try:
		listing.clearCodeUnits(addr, addr.add(dtype.getLength() - 1), False)
		listing.createData(addr, dtype)
	except Exception as e:
		Msg.warn(None, "Type apply failed: %s error: %s" % (new_name, str(e)))


# -----------------------------
# Entry point
# -----------------------------


def main():
	count = 0
	for sym in symbolTable.getAllSymbols(True):
		if sym.getSymbolType() != SymbolType.LABEL:
			continue
		if not sym.getName().startswith("DAT_"):
			continue

		new_name, dtype = analyze_symbol(sym)
		apply(sym, new_name, dtype)
		count += 1

	Msg.info(None, "Smart-renamed %d DAT_ globals" % count)


main()
