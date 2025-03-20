from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import StructureDataType, PointerDataType, CategoryPath
from ghidra.program.model.listing import CodeUnit

# Define common Pascal runtime function prefixes
PASCAL_PREFIXES = ["_P$", "SYSTEM.", "SYS_", "FPC_"]

def is_pascal_function(name):
    """Check if a function name matches Pascal-style naming"""
    return any(name.startswith(prefix) for prefix in PASCAL_PREFIXES)

def find_pascal_functions():
    """Find and rename Pascal-style functions"""
    symbols = currentProgram.getSymbolTable().getSymbolIterator()
    
    for sym in symbols:
        if sym.getSymbolType() == SymbolType.FUNCTION:
            name = sym.getName()
            if is_pascal_function(name):
                func = getFunctionAt(sym.getAddress())
                if func:
                    print("Found Pascal function: {} at {}", (name,func.getEntryPoint() ))
                    # Rename the function to be more readable (optional)
                    # func.setName(name.replace("_P$", ""), ghidra.program.model.symbol.SourceType.USER_DEFINED)

def find_vmt_tables():
    """Find potential VMT (Virtual Method Tables) used in Lazarus/FPC"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")
    
    for block in currentProgram.getMemory().getBlocks():
        if not block.isExecute():
            continue
        
        addr = block.getStart()
        while addr < block.getEnd():
            refs = getReferencesTo(addr)
            if len(refs) > 5:  # VMT tables often have many references
                print("Potential VMT table at: {}", addr)
                vmt_addr = "VMT_" + addr.toString()
                struct = StructureDataType(vmt_category, vmt_addr, 0)
                struct.add(PointerDataType(), 8, "MethodPtr1", "")
                struct.add(PointerDataType(), 8, "MethodPtr2", "")
                struct.add(PointerDataType(), 8, "MethodPtr3", "")
                struct.add(PointerDataType(), 8, "MethodPtr4", "")
                
                applyDataType(addr, struct)
            addr = addr.add(8)

def run():
    print("\n--- Recovering Pascal Function Names ---\n")
    find_pascal_functions()
    
    print("\n--- Searching for Virtual Method Tables (VMTs) ---\n")
    find_vmt_tables()
    
    print("\n--- Pascal Type Recovery Completed ---\n")

run()
