from ghidra.program.model.symbol import SymbolTable, Symbol, SourceType, SymbolType
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import FunctionManager
# from ghidra.program.model.symbol import Function
from ghidra.program.model.listing import Function
from ghidra.util.task import TaskMonitor

# Mapping of dsound.dll ordinals to function names (example values)
DSOUND_ORDINALS = {
	1: "dsoundunknown_1",
	2: "DirectSoundCreate",
	3: "DirectSoundEnumerateA",
	4: "DirectSoundEnumerateW",
	5: "DirectSoundCaptureCreate",
	6: "DirectSoundCaptureEnumerateA",
	7: "DirectSoundCaptureEnumerateW",
	8: "DirectSoundFullDuplexCreate",
	9: "DllCanUnloadNow",
	10: "DllGetClassObject",
	11: "GetDeviceID"
}



def resolve_dsound_ordinals():
	"""Resolve and rename ordinal-based imports from dsound.dll."""
	program = getCurrentProgram()
	if not program:
		print("Error: No active program in Ghidra.")
		return

	symbol_table = program.getSymbolTable()
	monitor = TaskMonitor.DUMMY
	updated_count = 0

	for symbol in symbol_table.getAllSymbols(True):
		if not symbol.isExternal():
			continue

		name = symbol.getName()
		parent_namespace = symbol.getParentNamespace()
		if not parent_namespace:
			continue

		parent_library = parent_namespace.getName().lower()

		# Ensure it's from dsound.dll
		if parent_library != "dsound.dll":
			continue

		ordinal = None

		# Extract ordinal from different naming styles
		if name.startswith("Ordinal_"):
			try:
				ordinal = int(name.split("_")[1])
			except ValueError:
				continue
		elif name.isdigit():  # Some symbols are just numbers
			ordinal = int(name)
		elif name.startswith("_") and name[1:].isdigit():  # Prefixed with _
			ordinal = int(name[1:])
		elif name.startswith("@") and name[1:].isdigit():  # Some compilers use '@'
			ordinal = int(name[1:])

		if ordinal and ordinal in DSOUND_ORDINALS:
			function_name = DSOUND_ORDINALS[ordinal]

			try:
				# Rename the symbol using setName()
				symbol.setName(function_name, SourceType.USER_DEFINED)
				print(f"Resolved: Ordinal_{ordinal} -> {function_name}")
				updated_count += 1
			except Exception as e:
				print(f"Failed to rename Ordinal_{ordinal}: {e}")

	print(f"\nFinished resolving {updated_count} ordinal imports from dsound.dll.")



def old2resolve_dsound_ordinals():
	"""Resolve and rename ordinal-based imports from dsound.dll."""
	program = getCurrentProgram()
	if not program:
		print("Error: No active program in Ghidra.")
		return

	symbol_table = program.getSymbolTable()
	monitor = TaskMonitor.DUMMY
	updated_count = 0

	for symbol in symbol_table.getAllSymbols(True):
		if not symbol.isExternal():
			continue

		name = symbol.getName()
		parent_namespace = symbol.getParentNamespace()
		if not parent_namespace:
			continue

		parent_library = parent_namespace.getName().lower()

		# Ensure it's from dsound.dll
		if parent_library != "dsound.dll":
			continue

		ordinal = None

		# Try extracting the ordinal from various naming styles
		if name.startswith("Ordinal_"):
			try:
				ordinal = int(name.split("_")[1])
			except ValueError:
				continue
		elif name.isdigit():  # Some symbols may just be numbers
			ordinal = int(name)
		elif name.startswith("_") and name[1:].isdigit():  # Sometimes prefixed with _
			ordinal = int(name[1:])
		elif name.startswith("@") and name[1:].isdigit():  # Some compilers prefix with '@'
			ordinal = int(name[1:])

		if ordinal and ordinal in DSOUND_ORDINALS:
			function_name = DSOUND_ORDINALS[ordinal]

			try:
				# Rename the symbol using setName()
				symbol.setName(function_name, SourceType.USER_DEFINED)
				print(f"Resolved: Ordinal_{ordinal} -> {function_name}")
				updated_count += 1
			except Exception as e:
				print(f"Failed to rename Ordinal_{ordinal}: {e}")

	print(f"\nFinished resolving {updated_count} ordinal imports from dsound.dll.")



def oldresolve_dsound_ordinals():
	"""Resolve and rename ordinal-based imports from dsound.dll."""
	program = getCurrentProgram()  # Ensure we get the current active program
	if not program:
		print("Error: No active program in Ghidra.")
		return

	symbol_table = program.getSymbolTable()
	monitor = TaskMonitor.DUMMY
	updated_count = 0

	for symbol in symbol_table.getAllSymbols(True):
		if not symbol.isExternal():
			continue

		name = symbol.getName()
		parent_namespace = symbol.getParentNamespace()
		if not parent_namespace:
			continue

		parent_library = parent_namespace.getName()

		# Check if the symbol is from dsound.dll and is an ordinal (e.g., "Ordinal_5")
		if parent_library.lower() == "dsound.dll" and name.startswith("Ordinal_"):
			try:
				ordinal = int(name.split("_")[1])  # Extract ordinal number
				if ordinal in DSOUND_ORDINALS:
					function_name = DSOUND_ORDINALS[ordinal]

					# Rename the function in Ghidra
					try:
						symbol_table.renameSymbol(symbol, function_name, monitor)
						print(f"Resolved: {ordinal} -> {function_name}")
						updated_count += 1
					except Exception as e:
						print(f"Failed to rename {name}: {e}")

			except ValueError:
				print(f"Skipping invalid ordinal name: {name}")

	print(f"\nFinished resolving {updated_count} ordinal imports from dsound.dll.")

def xxresolve_dsound_ordinals():
	"""Resolve and rename ordinal-based imports from dsound.dll."""
	program = currentProgram  # No parentheses needed
	if not program:
		print("Error: No active program in Ghidra.")
		return

	symbol_table = program.getSymbolTable()
	monitor = TaskMonitor.DUMMY
	updated_count = 0

	for symbol in symbol_table.getAllSymbols(True):
		if not symbol.isExternal():
			continue

		name = symbol.getName()
		parent_namespace = symbol.getParentNamespace()
		if not parent_namespace:
			continue

		parent_library = parent_namespace.getName()

		# Check if the symbol is from dsound.dll and is an ordinal (e.g., "Ordinal_5")
		if parent_library.lower() == "dsound.dll" and name.startswith("Ordinal_"):
			try:
				ordinal = int(name.split("_")[1])  # Extract ordinal number
				if ordinal in DSOUND_ORDINALS:
					function_name = DSOUND_ORDINALS[ordinal]

					# Rename the function in Ghidra
					symbol_table.renameSymbol(symbol, function_name, monitor)
					print(f"Resolved: {ordinal} -> {function_name}")
					updated_count += 1

			except ValueError:
				print(f"Skipping invalid ordinal name: {name}")

	print(f"\nFinished resolving {updated_count} ordinal imports from dsound.dll.")

# Run the script
resolve_dsound_ordinals()
def xresolve_dsound_ordinals():
	"""Resolve and rename ordinal-based imports from dsound.dll."""
	program = currentProgram()
	symbol_table = program.getSymbolTable()
	function_manager = program.getFunctionManager()
	monitor = TaskMonitor.DUMMY

	updated_count = 0

	# Iterate over all symbols
	for symbol in symbol_table.getSymbolIterator(SymbolType.LABEL, True):
		if not symbol.isExternal():
			continue

		name = symbol.getName()
		parent_library = symbol.getParentNamespace().getName()

		# Check if the symbol is from dsound.dll and is an ordinal (e.g., "Ordinal_5")
		if parent_library.lower() == "dsound.dll" and name.startswith("Ordinal_"):
			try:
				ordinal = int(name.split("_")[1])  # Extract ordinal number
				if ordinal in DSOUND_ORDINALS:
					function_name = DSOUND_ORDINALS[ordinal]

					# Rename the function in Ghidra
					symbol_table.renameSymbol(symbol, function_name, monitor)
					print(f"Resolved ordinal {ordinal} -> {function_name}")
					updated_count += 1

			except ValueError:
				print(f"Skipping invalid ordinal name: {name}")

	print(f"\nFinished resolving {updated_count} ordinal imports from dsound.dll.")

# Run the script
resolve_dsound_ordinals()
