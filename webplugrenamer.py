#@author 
#@category Refactoring
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolTable

FUNC_NAME = "convertOrThrowBasedOnMode"
FUNC_ADDR = "0x1005d70f"  # Replace with your function address

RENAME_LOCALS = {
    "cVar1": "mode",
    "bVar2": "sourceStr",
    "pbVar3": "resultStr",
    "_Str": "rawText",
    "_Str_00": "rawTextFallback",
    "sVar4": "len"
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
            param.setName("inputContext", SourceType.USER_DEFINED)
        elif i == 1:
            param.setName("outStrPtr", SourceType.USER_DEFINED)
        elif i == 2:
            param.setName("inStr", SourceType.USER_DEFINED)

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

def decompileFunction(func):
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    res = decompiler.decompileFunction(func, 60, monitor)
    if res and res.decompileCompleted():
        return res.getDecompiledFunction()
    return None

main()
