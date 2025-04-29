import ghidra
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StructureDataType, PointerDataType
from ghidra.program.model.listing import VariableStorage

# Configuration dictionary for renaming (extendable for multiple functions)
RENAME_CONFIG = [
    {
        'function_address': 0x1000dbcc,
        'new_function_name': 'InitializeSystemConfig',
        'return_type': 'SystemConfig*',
        'parameters': [],  # No parameters for this function
        'variables': [
            {'old_name': 'uVar1', 'new_name': 'tempFlag', 'type': 'uint8_t'},
            {'old_name': 'puVar2', 'new_name': 'tempPtr', 'type': 'void*'},
            {'old_name': 'pvVar3', 'new_name': 'allocatedMemory', 'type': 'void*'},
            {'old_name': 'puVar4', 'new_name': 'fieldPtr', 'type': 'void*'},
            {'old_name': 'sVar5', 'new_name': 'stringLength', 'type': 'size_t'},
            {'old_name': 'puVar6', 'new_name': 'bufferPtr', 'type': 'uint8_t*'},
            {'old_name': 'iVar7', 'new_name': 'loopCounter', 'type': 'int'},
            {'old_name': 'extraout_ECX', 'new_name': 'this', 'type': 'SystemConfig*'},
        ]
    },
    {
        'function_address': 0x10008d7c,
        'new_function_name': 'CleanupStringArray',
        'return_type': 'void',
        'parameters': [
            {'name': 'this', 'type': 'StringContainer*', 'index': 0}
        ],
        'variables': [
            {'old_name': 'pbVar1', 'new_name': 'endPtr', 'type': 'std::string*'},
            {'old_name': 'this', 'new_name': 'currentStr', 'type': 'std::string*'}
        ]
    }
]

def create_data_type(type_name, is_pointer=False):
    """Create a data type if it doesn't exist."""
    dtm = currentProgram.getDataTypeManager()
    data_type = dtm.getDataType('/' + type_name)
    
    if data_type is None and not is_pointer:
        # Create a placeholder structure for SystemConfig or StringContainer
        data_type = StructureDataType(type_name, 0)
        dtm.addDataType(data_type, None)
        print("Created structure " + type_name)
    
    if is_pointer:
        base_type = dtm.getDataType('/' + type_name.rstrip('*'))
        if base_type is None:
            base_type = StructureDataType(type_name.rstrip('*'), 0)
            dtm.addDataType(base_type, None)
        data_type = PointerDataType(base_type)
        dtm.addDataType(data_type, None)
        print("Created pointer type " + type_name)
    
    return data_type

def set_variable_type(variable, type_name):
    """Set the data type of a variable."""
    try:
        data_type = currentProgram.getDataTypeManager().getDataType('/' + type_name)
        if data_type is None:
            data_type = create_data_type(type_name, '*' in type_name)
        if data_type:
            variable.setDataType(data_type, False, True, SourceType.USER_DEFINED)
        else:
            print("Warning: Could not set type " + type_name + " for " + variable.getName())
    except Exception as e:
        print("Error setting type for " + variable.getName() + ": " + str(e))

def rename_function_and_variables(config):
    """Rename a function, its parameters, and local variables."""
    try:
        # Get the function at the specified address
        addr = currentProgram.getAddressFactory().getAddress(hex(config['function_address']))
        func = getFunctionAt(addr)
        if func is None:
            print("Error: No function found at address " + hex(config['function_address']))
            return

        # Rename the function
        func.setName(config['new_function_name'], SourceType.USER_DEFINED)
        print("Renamed function to " + config['new_function_name'])

        # Set return type
        return_type = create_data_type(config['return_type'], '*' in config['return_type'])
        if return_type:
            func.setReturnType(return_type, SourceType.USER_DEFINED)
            print("Set return type to " + config['return_type'])
        else:
            print("Warning: Could not set return type " + config['return_type'])

        # Set calling convention to __fastcall
        func.setCallingConvention('__fastcall')
        print("Set calling convention to __fastcall")

        # Rename parameters (if any)
        for param in config['parameters']:
            param_index = param.get('index', 0)
            if param_index < len(func.getParameters()):
                param_obj = func.getParameters()[param_index]
                param_obj.setName(param['name'], SourceType.USER_DEFINED)
                set_variable_type(param_obj, param['type'])
                print("Renamed parameter " + str(param_index) + " to " + param['name'])
            else:
                print("Warning: Parameter index " + str(param_index) + " out of range.")

        # Get all variables (local and stack)
        local_vars = func.getAllVariables()  # Includes stack and register variables
        decompiler = ghidra.app.decompiler.DecompInterface()
        decompiler.openProgram(currentProgram)
        decomp_result = decompiler.decompileFunction(func, 60, None)
        
        high_vars = None
        if decomp_result and decomp_result.getHighFunction():
            high_func = decomp_result.getHighFunction()
            local_symbol_map = high_func.getLocalSymbolMap()
            high_vars = local_symbol_map.getSymbols()

        # Rename variables
        for var_config in config['variables']:
            old_name = var_config['old_name']
            new_name = var_config['new_name']
            found = False

            # Check local variables
            for var in local_vars:
                if var.getName() == old_name:
                    var.setName(new_name, SourceType.USER_DEFINED)
                    set_variable_type(var, var_config['type'])
                    print("Renamed variable " + old_name + " to " + new_name + " with type " + var_config['type'])
                    found = True
                    break

            # Check high-level decompiler variables
            if not found and high_vars:
                for high_var in high_vars:
                    if high_var.getName() == old_name:
                        high_var.setName(new_name)
                        print("Renamed decompiler variable " + old_name + " to " + new_name)
                        found = True
                        break

            if not found:
                print("Warning: Variable " + old_name + " not found in function. Check decompiler output or re-analyze.")

    except Exception as e:
        print("Error processing function at " + hex(config['function_address']) + ": " + str(e))

def main():
    """Main function to process all functions in the config."""
    for config in RENAME_CONFIG:
        print("Processing function at address " + hex(config['function_address']))
        rename_function_and_variables(config)
    print("Renaming complete.")

if __name__ == "__main__":
    main()