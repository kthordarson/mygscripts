# Abuse: rename level functions and fix Game::load_level signature
# @author kth
# @category mygscripts
# @keybinding
# @menupath Tools.AutoFix.Level
# @toolbar

try:
	from ghidra.ghidra_builtins import (
		askChoices,
		askDirectory,
		askFile,
		currentProgram,
		getFunctionContaining,
		getReferencesTo,
		getSymbol,
		setBackgroundColor,
		toAddr,
		getBytes,
		addr_space,
		addr_fact
	)
except ImportError:
	pass
from ghidra.program.model.symbol import SourceType
# from ghidra.program.model.data import *
from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import (
	StructureDataType,
	PointerDataType,
	FunctionDefinitionDataType,
	UnsignedLongLongDataType,
	DWordDataType,
	ByteDataType,
	WordDataType,
	QWordDataType,
	DataTypeConflictHandler,
)

monitor = ConsoleTaskMonitor()

program = currentProgram
dtm = program.getDataTypeManager()
fm = program.getFunctionManager()

def get_func_by_name(name):
	funcs = fm.getFunctions(True)
	for f in funcs:
		if f.getName() == name:
			return f
	return None

def rename_func(old, new):
	f = get_func_by_name(old)
	if f:
		f.setName(new, SourceType.USER)
		print("+] Renamed function:", new)

if __name__ == "__main__":
	load_func = get_func_by_name("FUN_load_level")
	if load_func:
		load_func.setName("Game::load_level", SourceType.USER)

		sig = "void load_level(char const *name)"
		load_func.setSignature(
			load_func.getCallingConventionName(),
			sig,
			SourceType.USER
		)
		print("+] Fixed Game::load_level signature")

	dtor = get_func_by_name("FUN_level_destructor")
	if dtor:
		dtor.setName("level::~level", SourceType.USER)
		dtor.setFunctionType(Function.FunctionType.DESTRUCTOR)
		print("+] Marked level::~level as destructor")

	struct_name = "level"
	if not dtm.getDataType("/reverse/" + struct_name):
		level_struct = StructureDataType("/reverse", struct_name, 0x98)

		level_struct.add(PointerDataType.dataType, 8, "vtable", None)
		level_struct.add(DWordDataType.dataType, 4, "width", None)
		level_struct.add(DWordDataType.dataType, 4, "height", None)
		level_struct.add(PointerDataType.dataType, 8, "palette_data", None)

		level_struct.insertAtOffset(0x48, PointerDataType.dataType, 8, "map_fg", None)
		level_struct.insertAtOffset(0x58, PointerDataType.dataType, 8, "map_bg", None)
		level_struct.insertAtOffset(0x68, PointerDataType.dataType, 8, "obj_map", None)
		level_struct.insertAtOffset(0x78, PointerDataType.dataType, 8, "light_map", None)

		dtm.addDataType(level_struct, DataTypeConflictHandler.DEFAULT_HANDLER)
		print("+] Created level structure")

	print("✓] Auto-fix complete")
