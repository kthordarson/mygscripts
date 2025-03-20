# Ghidra script to improve Free Pascal decompilation
# Scans for Pascal-style symbols, renames functions, and reconstructs data types

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import StructureDataType, DataTypeConflictHandler
from ghidra.program.model.listing import FunctionManager

# Function name patterns common in Free Pascal binaries
pascal_prefixes = ["_P$", "SYS_", "FPC_", "SYSTEM_", "RTL_"]

def rename_pascal_functions():
    """Finds and renames Pascal-style functions."""
    symbol_table = currentProgram.getSymbolTable()
    functions = currentProgram.getFunctionManager().getFunctions(True)
    
    renamed_count = 0
    for func in functions:
        func_name = func.getName()
        for prefix in pascal_prefixes:
            if func_name.startswith(prefix):
                new_name = func_name.replace("_P$", "").replace("SYS_", "").replace("FPC_", "Fpc_")
                symbol_table.getSymbol(func_name, func.getEntryPoint()).setName(new_name, ghidra.util.task.TaskMonitor.DUMMY)
                renamed_count += 1
                print("Renamed {} → {}", (func_name, new_name))
    
    print("Renamed {} Pascal-style functions.", renamed_count)

def find_vmt_tables():
    """Finds possible Virtual Method Tables (VMT) used in Free Pascal."""
    data = currentProgram.getListing()
    for symbol in currentProgram.getSymbolTable().getAllSymbols(True):
        if "_VMT" in symbol.getName():
            print("Possible VMT found: {} at {}", (symbol.getName(), symbol.getAddress()))
            # Rename as Pascal-style VMT
            new_name = symbol.getName().replace("_VMT", "VMT")
            symbol.setName(new_name, ghidra.util.task.TaskMonitor.DUMMY)

def recover_structures():
    """Attempts to create Pascal-style record (struct) data types."""
    dtm = currentProgram.getDataTypeManager()
    
    # Example of a basic Pascal record (struct)
    pascal_record = StructureDataType("TMyRecord", 0)
    pascal_record.add(dtm.getDataType("/int"), 4, "ID", None)
    pascal_record.add(dtm.getDataType("/float"), 4, "Value", None)

    dtm.addDataType(pascal_record, DataTypeConflictHandler.REPLACE_HANDLER)
    print("Added Pascal record structure: TMyRecord")

def main():
    rename_pascal_functions()
    find_vmt_tables()
    recover_structures()

main()
