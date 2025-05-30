from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Function
from ghidra.app.util import NamespaceUtils

def resolve_ordinal_symbols():
	# Get the current program
	program = getCurrentProgram()
	symbol_table = program.getSymbolTable()
	function_mgr = program.getFunctionManager()
	memory = program.getMemory()

	# Dictionary to store known ordinal mappings
	# Format: (dll_name.lower(), ordinal): (function_name, param_count, return_type)
	ordinal_mappings = {("kernel32.dll", 1): ("HeapAlloc", 3, "pointer"),		("user32.dll", 16): ("MessageBoxA", 4, "int"),		("wsock32.dll", 1): ("accept", 3, "socket"),		("wsock32.dll", 2): ("bind", 3, "int"),		("wsock32.dll", 3): ("closesocket", 1, "int"),		("wsock32.dll", 4): ("connect", 3, "int"),		("wsock32.dll", 6): ("gethostbyname", 1, "pointer"),		("wsock32.dll", 11): ("gethostname", 2, "int"),		("wsock32.dll", 13): ("getsockname", 3, "int"),		("wsock32.dll", 16): ("htonl", 1, "uint"),		("wsock32.dll", 17): ("htons", 1, "uint"),		("wsock32.dll", 22): ("listen", 2, "int"),		("wsock32.dll", 23): ("ntohl", 1, "uint"),		("wsock32.dll", 24): ("ntohs", 1, "uint"),		("wsock32.dll", 26): ("recv", 4, "int"),		("wsock32.dll", 27): ("recvfrom", 6, "int"),		("wsock32.dll", 30): ("send", 4, "int"),		("wsock32.dll", 31): ("sendto", 6, "int"),		("wsock32.dll", 33): ("setsockopt", 5, "int"),		("wsock32.dll", 34): ("shutdown", 2, "int"),		("wsock32.dll", 35): ("socket", 3, "socket"),		("wsock32.dll", 52): ("WSAStartup", 2, "int"),		("wsock32.dll", 55): ("WSACleanup", 0, "int"),		("wsock32.dll", 57): ("WSAGetLastError", 0, "int"),}

	# Get all external references
	# symbols = symbol_table.getExternalSymbols()
	symbols = [k for k in symbol_table.getExternalSymbols()]
	for symbol in symbols:
		name = symbol.getName()
		# Look for ordinal-only symbols
		if name.startswith("Ordinal_"):
			try:
				ordinal_num = int(name.split("_")[1])
				# dll_name = ext_loc.getLibraryName().lower()
				dll_name = symbol.getParentSymbol().getName()
				print(f'Checking {dll_name} ordinal {ordinal_num}')
				# Check if we have a mapping for this ordinal
				key = (dll_name.lower(), ordinal_num)
				if key in ordinal_mappings:
					func_name, param_count, ret_type = ordinal_mappings[key]

					# Get or create the function at this address
					address = symbol.getAddress()
					func = function_mgr.getFunctionAt(address)

					if func is None:
						func = function_mgr.createFunction(func_name, address, None, SourceType.IMPORTED)

					# Set function name
					symbol.setName(func_name, SourceType.IMPORTED)

					# Set calling convention to __stdcall (standard for Windows DLLs)
					func.setCallingConvention("__stdcall")

					# Clear existing parameters and set new ones
					func.removeAllParameters()

					# Add generic parameters based on count
					for i in range(param_count):
						param = func.addParameter(None, "param_" + str(i + 1), "int", 4)

					# Set return type based on our mapping
					if ret_type == "pointer":
						func.setReturnType(program.getDataTypeManager().getPointer(None), SourceType.IMPORTED)
					elif ret_type == "int":
						func.setReturnType(program.getDataTypeManager().getDataType("/int"), SourceType.IMPORTED)
					elif ret_type == "uint":
						func.setReturnType(program.getDataTypeManager().getDataType("/uint"), SourceType.IMPORTED)
					elif ret_type == "socket":
						# Using uint32 as a stand-in for SOCKET type
						func.setReturnType(program.getDataTypeManager().getDataType("/uint"), SourceType.IMPORTED)

					print("Renamed {} from {} to {} at {}".format(dll_name, name, func_name, address))

				else:
					print("No mapping found for {} ordinal {}".format(dll_name, ordinal_num))

			except Exception as e:
				print("Error processing {}: {}".format(name, str(e)))

if __name__ == "__main__":
	resolve_ordinal_symbols()