from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.data import PointerDataType, UnicodeDataType, VoidDataType, UnsignedIntegerDataType
from ghidra.program.model.listing import Function

def create_msi_signatures():
    # Get program components
    dtm = currentProgram.getDataTypeManager()
    fm = currentProgram.getFunctionManager()
    
    # Common MSI function signatures
    msi_functions = [
        {
            "name": "MsiOpenDatabaseW",
            "return_type": UnsignedIntegerDataType(),
            "params": [
                ("szDatabasePath", PointerDataType(UnicodeDataType())),
                ("szPersist", PointerDataType(UnicodeDataType())),
                ("phDatabase", PointerDataType(PointerDataType(VoidDataType())))
            ]
        },
        {
            "name": "MsiDatabaseOpenViewW",
            "return_type": UnsignedIntegerDataType(),
            "params": [
                ("hDatabase", PointerDataType(VoidDataType())),
                ("szQuery", PointerDataType(UnicodeDataType())),
                ("phView", PointerDataType(PointerDataType(VoidDataType())))
            ]
        },
        {
            "name": "MsiViewExecute",
            "return_type": UnsignedIntegerDataType(),
            "params": [
                ("hView", PointerDataType(VoidDataType())),
                ("hRecord", PointerDataType(VoidDataType()))
            ]
        },
        {
            "name": "MsiViewFetch",
            "return_type": UnsignedIntegerDataType(),
            "params": [
                ("hView", PointerDataType(VoidDataType())),
                ("phRecord", PointerDataType(PointerDataType(VoidDataType())))
            ]
        },
        {
            "name": "MsiRecordGetStringW",
            "return_type": UnsignedIntegerDataType(),
            "params": [
                ("hRecord", PointerDataType(VoidDataType())),
                ("iField", UnsignedIntegerDataType()),
                ("szValueBuf", PointerDataType(UnicodeDataType())),
                ("pcchValueBuf", PointerDataType(UnsignedIntegerDataType()))
            ]
        },
        {
            "name": "MsiCloseHandle",
            "return_type": UnsignedIntegerDataType(),
            "params": [
                ("hAny", PointerDataType(VoidDataType()))
            ]
        },
        {
            "name": "MsiCreateRecord",
            "return_type": PointerDataType(VoidDataType()),  # Returns MSIHANDLE
            "params": [
                ("cParams", UnsignedIntegerDataType())
            ]
        }
    ]

    # Create function definitions
    func_defs = {}
    for func_info in msi_functions:
        func_def = FunctionDefinitionDataType(func_info["name"])
        func_def.setReturnType(func_info["return_type"])
        params = []
        for param_name, param_type in func_info["params"]:
            param = ParameterDefinitionImpl(param_name, param_type, "")
            params.append(param)
        func_def.setArguments(params)
        func_defs[func_info["name"]] = dtm.addDataType(func_def, None)

    # Process external (imported) functions
    external_funcs = fm.getExternalFunctions()
    for func in external_funcs:
        func_name = func.getName()
        if func_name in func_defs:
            try:
                # Get the thunk address (where the import is actually referenced)
                thunk_addr = func.getEntryPoint()
                
                # Get or create the thunk function at this address
                thunk_func = fm.getFunctionAt(thunk_addr)
                if thunk_func is None:
                    thunk_func = fm.createFunction(func_name, thunk_addr, None, SourceType.IMPORTED)
                    print("Created thunk function: " + func_name + " at " + str(thunk_addr))
                
                if thunk_func is not None:
                    # Apply the signature
                    thunk_func.setSignature(func_defs[func_name], SourceType.IMPORTED)
                    print("Updated signature for: " + func_name + " at " + str(thunk_addr))
                else:
                    print("Failed to create thunk function: " + func_name + " at " + str(thunk_addr))
            except Exception as e:
                print("Error updating " + func_name + ": " + str(e))

# Run the script
if __name__ == "__main__":
    try:
        create_msi_signatures()
        print("MSI function signatures import completed!")
    except Exception as e:
        print("Error running script: " + str(e))