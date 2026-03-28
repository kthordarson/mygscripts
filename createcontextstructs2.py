from ghidra.program.model.data import StructureDataType, UnsignedIntegerDataType, UnsignedCharDataType, ArrayDataType, PointerDataType, VoidDataType
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor

def update_process_resource_data():
    dtm = currentProgram.getDataTypeManager()
    symbol_table = currentProgram.getSymbolTable()

    # Update GlobalContext
    global_context = dtm.getDataType("/GlobalContext")
    if global_context:
        global_context.add(UnsignedIntegerDataType(), 4, "offsetLow", "Low 32 bits of offset")
        global_context.add(UnsignedIntegerDataType(), 4, "offsetHigh", "High 32 bits of offset")
        print("Updated GlobalContext with offset fields")
    else:
        print("Error: GlobalContext not found")

    # Define ArrayDescriptor
    array_descriptor = StructureDataType("ArrayDescriptor", 0)
    array_descriptor.add(ArrayDataType(UnsignedIntegerDataType(), 6, 4), "reserved", "Unused")
    array_descriptor.add(UnsignedIntegerDataType(), 4, "size", "Total size")
    array_descriptor.add(UnsignedIntegerDataType(), 4, "position", "Current position")
    dtm.addDataType(array_descriptor, None)
    print("Created ArrayDescriptor structure")

    # Define ResourceContext
    resource_context = StructureDataType("ResourceContext", 0)
    resource_context.add(ArrayDataType(UnsignedIntegerDataType(), 1, 4), "reserved1", "Unused")
    resource_context.add(UnsignedIntegerDataType(), 4, "type", "Resource type")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 22, 1), "reserved2", "Padding")
    resource_context.add(UnsignedCharDataType(), 1, "flushRequired", "Flush flag")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 1, 1), "reserved3", "Padding")
    resource_context.add(UnsignedLongLongDataType(), 8, "offset1", "First offset")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 2048, 1), "errorMessage", "Error message")
    resource_context.add(UnsignedLongLongDataType(), 8, "offset2", "Second offset")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 0x1004, 1), "reserved4", "Padding")
    resource_context.add(PointerDataType(), 4, "resourceList", "Resource list")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 20, 1), "reserved5", "Padding")
    resource_context.add(UnsignedLongLongDataType(), 8, "value1", "First value")
    resource_context.add(UnsignedLongLongDataType(), 8, "value2", "Second value")
    resource_context.add(UnsignedLongLongDataType(), 8, "value3", "Third value")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 0x14, 1), "reserved6", "Padding")
    resource_context.add(UnsignedIntegerDataType(), 4, "blockType", "Block type")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 4, 1), "blockData", "Block data")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 0x23, 1), "reserved7", "Padding")
    resource_context.add(UnsignedCharDataType(), 1, "flag1", "Flag")
    resource_context.add(UnsignedIntegerDataType(), 4, "state", "State")
    resource_context.add(UnsignedCharDataType(), 1, "flag2", "Flag")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 16, 1), "buffer1", "First buffer")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 16, 1), "buffer2", "Second buffer")
    resource_context.add(UnsignedCharDataType(), 1, "hashValid", "Hash valid flag")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 8, 1), "hashData", "Hash data")
    resource_context.add(UnsignedCharDataType(), 1, "flag3", "Flag")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 0x21, 1), "reserved8", "Padding")
    resource_context.add(UnsignedIntegerDataType(), 4, "index", "Index")
    resource_context.add(UnsignedCharDataType(), 1, "errorFlag", "Error flag")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 0xc, 1), "reserved9", "Padding")
    resource_context.add(UnsignedIntegerDataType(), 4, "dataValue", "Data value")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 2048, 1), "stringData", "String data")
    resource_context.add(UnsignedCharDataType(), 1, "flag4", "Flag")
    resource_context.add(UnsignedCharDataType(), 1, "flag5", "Flag")
    resource_context.add(UnsignedCharDataType(), 1, "flag6", "Flag")
    resource_context.add(UnsignedCharDataType(), 1, "flag7", "Flag")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 255, 1), "string1", "First string")
    resource_context.add(ArrayDataType(UnsignedCharDataType(), 255, 1), "string2", "Second string")
    resource_context.add(UnsignedIntegerDataType(), 4, "value4", "Fourth value")
    resource_context.add(UnsignedIntegerDataType(), 4, "value5", "Fifth value")
    dtm.addDataType(resource_context, None)
    print("Created ResourceContext structure")

    # Find FUN_00402210
    func = None
    for symbol in symbol_table.getSymbolIterator():
        if symbol.getName() == "FUN_00402210" and symbol.getSymbolType().isFunction():
            func = getFunctionAt(symbol.getAddress())
            break

    if not func:
        print("Error: Could not find FUN_00402210")
        return

    # Update function signature
    func.setReturnType(VoidDataType(), SourceType.USER_DEFINED)
    params = func.getParameters()
    if len(params) >= 4:
        params[0].setDataType(PointerDataType(global_context), SourceType.USER_DEFINED)
        params[0].setName("context", SourceType.USER_DEFINED)
        params[1].setDataType(PointerDataType(array_descriptor), SourceType.USER_DEFINED)
        params[1].setName("array", SourceType.USER_DEFINED)
        params[2].setDataType(UnsignedIntegerDataType(), SourceType.USER_DEFINED)
        params[2].setName("count", SourceType.USER_DEFINED)
        params[3].setDataType(PointerDataType(resource_context), SourceType.USER_DEFINED)
        params[3].setName("resource", SourceType.USER_DEFINED)
        print("Updated parameters to GlobalContext*, ArrayDescriptor*, uint32_t, ResourceContext*")
    else:
        print("Warning: Insufficient parameters in FUN_00402210")

    # Rename function
    func.setName("ProcessResourceData", SourceType.USER_DEFINED)
    print("Renamed function to ProcessResourceData")

    # Re-decompile
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
    print("Re-decompiled ProcessResourceData to reflect new signature")

if __name__ == "__main__":
    try:
        update_process_resource_data()
        print("Script completed successfully")
    except Exception as e:
        print(f"Script failed: {str(e)}")