```python
# Python script for Ghidra to create the GlobalContext structure
# Creates a structure with fields for resource processing and cryptographic operations
# Applies the structure to the 'global' variable in FUN_00403bba
# Run in Ghidra's Python interpreter

from ghidra.program.model.data import StructureDataType, UnsignedCharDataType, UnsignedIntegerDataType, PointerDataType, ArrayDataType
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor

def create_global_context_structure():
    # Get the current program's Data Type Manager
    dtm = currentProgram.getDataTypeManager()
    symbol_table = currentProgram.getSymbolTable()

    # Define the GlobalContext structure
    global_context = StructureDataType("GlobalContext", 0)

    # Add fields with offsets based on prior analysis
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x20f8, 1), "reserved1", "Reserved bytes before resourceBlock")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x251, 1), "resourceBlock", "Resource data block")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x2487, 1), "reserved2", "Reserved bytes")
	global_context.add(UnsignedIntegerDataType(), 4, "mode", "Processing mode")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 4, 1), "reserved3", "Padding")
	global_context.add(UnsignedIntegerDataType(), 4, "resourceCount", "Number of resources")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 28, 1), "reserved4", "Reserved bytes")
	global_context.add(UnsignedIntegerDataType(), 4, "version", "Version or state")
	global_context.add(UnsignedCharDataType(), 1, "flags", "System flags")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x1030, 1), "reserved5", "Reserved bytes")
	global_context.add(UnsignedIntegerDataType(), 4, "resourceId1", "First resource ID")
	global_context.add(UnsignedIntegerDataType(), 4, "resourceId2", "Second resource ID")
	global_context.add(UnsignedIntegerDataType(), 4, "resourceSize", "Resource data size")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x24, 1), "reserved6", "Reserved bytes")
	global_context.add(ArrayDataType(UnsignedIntegerDataType(), 0x4e, 4), "cryptoContext", "Cryptographic context")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x21, 1), "reserved7", "Reserved bytes")
	global_context.add(UnsignedCharDataType(), 1, "useCrypto", "Flag for cryptographic processing")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x2645, 1), "reserved8", "Reserved bytes")
	global_context.add(UnsignedCharDataType(), 1, "initialized", "Initialization flag")
	global_context.add(ArrayDataType(UnsignedCharDataType(), 0x10, 1), "reserved9", "Reserved bytes")
	global_context.add(UnsignedCharDataType(), 1, "processingDone", "Processing completion flag")

    # Verify the structure size (should cover at least 0x6cdc + 1)
    expected_size = 0x6cdc + 1
    actual_size = global_context.getLength()
    print(f"GlobalContext size: {hex(actual_size)} (expected at least {hex(expected_size)})")

    # Add the structure to the Data Type Manager
    existing_dt = dtm.getDataType("/GlobalContext")
    if existing_dt:
        dtm.removeDataType(existing_dt, TaskMonitor.DUMMY)
        print("Removed existing GlobalContext structure")
    dtm.addDataType(global_context, None)
    print("Created GlobalContext structure")

    # Apply the structure to the 'global' variable in FUN_00403bba
    try:
        # Find the function FUN_00403bba
        func = None
        for symbol in symbol_table.getSymbolIterator():
            if symbol.getName() == "FUN_00403bba" and symbol.getSymbolType().isFunction():
                func = getFunctionAt(symbol.getAddress())
                break

        if not func:
            print("Error: Could not find FUN_00403bba")
            return

        # Get the function's parameters
        params = func.getParameters()
        for param in params:
            if param.getName() == "global" or param.getName().startswith("param_"):
                # Set the parameter type to GlobalContext*
                param.setDataType(PointerDataType(global_context), SourceType.USER_DEFINED)
                print(f"Applied GlobalContext* to parameter {param.getName()} in FUN_00403bba")
                break
        else:
            print("Warning: No suitable parameter found in FUN_00403bba to apply GlobalContext*")

        # Re-decompile the function to update the decompiler output
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
        print("Re-decompiled FUN_00403bba to reflect GlobalContext")

    except Exception as e:
        print(f"Error applying GlobalContext to FUN_00403bba: {str(e)}")

if __name__ == "__main__":
    try:
        create_global_context_structure()
        print("Script completed successfully")
    except Exception as e:
        print(f"Script failed: {str(e)}")
```