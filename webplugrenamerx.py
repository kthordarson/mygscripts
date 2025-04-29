#@author 
#@category Refactoring
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface

FUNC_NAME = "cleanupMemory"
FUNC_ADDR = "0x1003ed4b"  # Replace with your function address

RENAME_LOCALS = {
    "param_1": "objPtr",
    "operator_delete": "freeMemoryBlock",  # If the operator_delete is used as a function call
}

def main():
    func = getFunctionAt(toAddr(FUNC_ADDR))
    if not func:
        print("Function not found at address: %s" % FUNC_ADDR)
        return

    func.setName(FUNC_NAME, SourceType.USER_DEFINED)
    print("Renamed function to: %s" % FUNC_NAME)

    params = func.getParameters()
    for i, param in enumerate(params):
        if i == 0:
            param.setName("objPtr", SourceType.USER_DEFINED)
            print("Renamed parameter to: objPtr")

    decompiled = decompileFunction(func)
    if decompiled is None:
        print("Failed to decompile function.")
        return

    # Access the symbol table for local variables
    symbol_table = currentProgram.getSymbolTable()
    func_symbols = symbol_table.getSymbols(func.getEntryPoint())
    
    for symbol in func_symbols:
        if symbol.getName() in RENAME_LOCALS:
            new_name = RENAME_LOCALS[symbol.getName()]
            symbol.setName(new_name, SourceType.USER_DEFINED)
            print("Renamed %s to %s" % (symbol.getName(), new_name))

    # Renaming locals
    # function = decompiled.getFunction()
    # local_symbols = function.getLocalVariables()

    # for symbol in local_symbols:
    #     old_name = symbol.getName()
    #     if old_name in RENAME_LOCALS:
    #         new_name = RENAME_LOCALS[old_name]
    #         symbol.setName(new_name, SourceType.USER_DEFINED)
    #         print("Renamed %s to %s" % (old_name, new_name))

def decompileFunction(func):
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    res = decompiler.decompileFunction(func, 60, monitor)
    if res and res.decompileCompleted():
        return res.getDecompiledFunction()
    return None

main()
