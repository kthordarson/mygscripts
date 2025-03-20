from ghidra.program.model.data import DataType, DataTypeManager
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.listing import FunctionManager, ParameterImpl, VariableStorage
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.util.task import TaskMonitor

def rename_function_arguments_and_locals():
    """Renames function arguments and local variables based on function signatures."""

    program = getCurrentProgram()
    if not program:
        print("Error: No active program in Ghidra.")
        return

    symbol_table = program.getSymbolTable()
    function_manager = program.getFunctionManager()
    monitor = TaskMonitor.DUMMY
    updated_count = 0

    for symbol in symbol_table.getAllSymbols(True):
        if not symbol.isExternal():
            continue

        if symbol.getSymbolType() != SymbolType.FUNCTION:
            continue

        function_name = symbol.getName()
        external_function = function_manager.getFunctionAt(symbol.getAddress())

        if not external_function:
            continue

        # Fetch the imported function signature
        imported_signature = external_function.getSignature()
        if not imported_signature:
            continue

        # Rename function parameters
        parameters = external_function.getParameters()

        for i, param in enumerate(parameters):
            try:
                # Extract argument name and data type
                expected_name = imported_signature.getArguments()[i].getName()
                expected_type = imported_signature.getArguments()[i].getDataType()

                # Rename the argument if necessary
                if param.getName() != expected_name:
                    param.setName(expected_name, SourceType.IMPORTED)

                # Set the correct data type
                if param.getDataType() != expected_type:
                    param.setDataType(expected_type, SourceType.IMPORTED)

                print(f"Updated {function_name}: Arg {i} -> {expected_name} ({expected_type})")

            except IndexError:
                print(f"Warning: {function_name} has more parameters than expected.")

        # Rename the local variables
        local_vars = external_function.getLocalVariables()

        for local in local_vars:
            local_type = local.getDataType()

            # Check for pointer variables
            if isinstance(local_type, PointerDataType):
                # Rename local variables that hold results (e.g., &param_2, &local_c)
                if "local_" in local.getName():
                    try:
                        local.setName(f"Out_{function_name}", SourceType.IMPORTED)
                        print(f"Renamed local var {local.getName()} -> Out_{function_name}")
                    except:
                        pass

            # Handle constant pointer (e.g., (PLONG)0x0) - treat as a special case for renaming
            if "0x0" in local.getName():  # Detect pointers initialized to 0
                try:
                    local.setName(f"NullPointer_{function_name}", SourceType.IMPORTED)
                    print(f"Renamed pointer {local.getName()} -> NullPointer_{function_name}")
                except:
                    pass

        updated_count += 1

    print(f"\nFinished updating {updated_count} function arguments and local variables.")

def rename_function_arguments_and_localsv2():
	"""Renames function arguments and local variables based on function signatures."""

	program = getCurrentProgram()
	if not program:
		print("Error: No active program in Ghidra.")
		return

	symbol_table = program.getSymbolTable()
	function_manager = program.getFunctionManager()
	monitor = TaskMonitor.DUMMY
	updated_count = 0

	for symbol in symbol_table.getAllSymbols(True):
		if not symbol.isExternal():
			continue

		if symbol.getSymbolType() != SymbolType.FUNCTION:
			continue

		function_name = symbol.getName()
		external_function = function_manager.getFunctionAt(symbol.getAddress())

		if not external_function:
			continue

		# Fetch the imported function signature
		imported_signature = external_function.getSignature()
		if not imported_signature:
			continue

		# Rename function parameters
		parameters = external_function.getParameters()

		for i, param in enumerate(parameters):
			try:
				# Extract argument name and data type
				expected_name = imported_signature.getArguments()[i].getName()
				expected_type = imported_signature.getArguments()[i].getDataType()

				# Rename the argument if necessary
				if param.getName() != expected_name:
					param.setName(expected_name, SourceType.IMPORTED)

				# Set the correct data type
				if param.getDataType() != expected_type:
					param.setDataType(expected_type, SourceType.IMPORTED)

				print(f"Updated {function_name}: Arg {i} -> {expected_name} ({expected_type})")

			except IndexError:
				print(f"Warning: {function_name} has more parameters than expected.")

		# Rename the local variables
		local_vars = external_function.getLocalVariables()

		for local in local_vars:
			local_type = local.getDataType()

			# Check for pointer variables
			if isinstance(local_type, PointerDataType):
				# Rename local variables that hold results (e.g., &local_c)
				if "local_" in local.getName():
					try:
						local.setName(f"Out_{function_name}", SourceType.IMPORTED)
						print(f"Renamed local var {local.getName()} -> Out_{function_name}")
					except:
						pass

		updated_count += 1

	print(f"\nFinished updating {updated_count} function arguments and local variables.")

def rename_function_returns_and_localsv1():
	"""Renames return values and local variables based on function signatures."""

	program = getCurrentProgram()
	if not program:
		print("Error: No active program in Ghidra.")
		return

	symbol_table = program.getSymbolTable()
	function_manager = program.getFunctionManager()
	monitor = TaskMonitor.DUMMY
	updated_count = 0

	for symbol in symbol_table.getAllSymbols(True):
		if not symbol.isExternal():
			continue

		if symbol.getSymbolType() != SymbolType.FUNCTION:
			continue

		function_name = symbol.getName()
		external_function = function_manager.getFunctionAt(symbol.getAddress())

		if not external_function:
			continue

		# Fetch the imported function signature
		imported_signature = external_function.getSignature()
		if not imported_signature:
			continue

		# Rename return variable
		return_type = imported_signature.getReturnType()
		if return_type:
			decompiled_func = external_function.getBody()
			instructions = program.getListing().getInstructions(decompiled_func, True)

			for instr in instructions:
				if instr.getFlowType().isCall():
					called_function = instr.getFlows()[0]
					if called_function == external_function.getEntryPoint():
						# Identify return variable (assumed to be assigned)
						for op_index in range(instr.getNumOperands()):
							op_refs = instr.getOpObjects(op_index)
							for op in op_refs:
								if op.toString().startswith("BVar"):  # Generic name
									try:
										op.setName("Result_" + function_name, SourceType.IMPORTED)
										print(f"Renamed return value for {function_name} -> {op.toString()}")
									except:
										pass

		# Rename local variables (example: local_1c for structure pointers)
		for param in external_function.getParameters():
			if param.isAutoParameter():
				continue  # Skip stack pointer, return address, etc.

			param_type = param.getDataType()
			if param_type and param_type.toString().startswith("struct"):
				# Identify local variable receiving struct output
				local_vars = external_function.getLocalVariables()
				for local in local_vars:
					if local.getDataType() == param_type and "local_" in local.getName():
						try:
							local.setName("Out_" + function_name, SourceType.IMPORTED)
							print(f"Renamed local var {local.getName()} -> Out_{function_name}")
						except:
							pass

		updated_count += 1

	print(f"\nFinished updating {updated_count} function return values and locals.")

def apply_imported_function_signatures():
	"""Renames function arguments and sets types based on imported symbols."""

	program = getCurrentProgram()
	if not program:
		print("Error: No active program in Ghidra.")
		return

	symbol_table = program.getSymbolTable()
	function_manager = program.getFunctionManager()
	data_type_manager = program.getDataTypeManager()
	monitor = TaskMonitor.DUMMY
	updated_count = 0

	for symbol in symbol_table.getAllSymbols(True):
		if not symbol.isExternal():
			continue

		if symbol.getSymbolType() != SymbolType.FUNCTION:
			continue

		function_name = symbol.getName()
		external_function = function_manager.getFunctionAt(symbol.getAddress())

		if not external_function:
			continue

		# Fetch the imported function signature
		imported_signature = external_function.getSignature()
		if not imported_signature:
			continue

		parameters = external_function.getParameters()

		for i, param in enumerate(parameters):
			try:
				# Get expected name and type from imported signature
				expected_name = imported_signature.getArguments()[i].getName()
				expected_type = imported_signature.getArguments()[i].getDataType()

				# Set the parameter name
				if param.getName() != expected_name:
					param.setName(expected_name, SourceType.IMPORTED)

				# Set the correct data type
				if param.getDataType() != expected_type:
					param.setDataType(expected_type, SourceType.IMPORTED)

				print(f"Updated {function_name}: Arg {i} -> {expected_name} ({expected_type})")

			except IndexError:
				print(f"Warning: {function_name} has more parameters than expected.")

		updated_count += 1

	print(f"\nFinished updating {updated_count} function signatures.")

if __name__ == "__main__":
	# Run the function
	# rename_function_returns_and_locals()
	rename_function_arguments_and_locals()
	# Run the function
	# apply_imported_function_signatures()
