#@author 
#@category Refactoring
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType

FUNC_NAME = "copyMemoryBlock"
FUNC_ADDR = "0x1003ebd0"  # Replace with your function address

# This dictionary maps the current variable names to new names for renaming
RENAME_LOCALS = {
    "this": "objectPtr",
    "param_1": "sourceData",
    "param_2": "endPointer",
    "puVar1": "objectPointer",
    "puVar2": "destPtr",
    "puVar3": "srcPtr"
}

FUNC_NAME = "copyMemoryBlock"
FUNC_ADDR = "0x1003ebd0"  # Replace with your function address

# This dictionary maps the current variable names to new names for renaming
RENAME_LOCALS = {
    "this": "objectPtr",
    "param_1": "sourceData",
    "param_2": "endPointer",
    "puVar1": "objectPointer",
    "puVar2": "destPtr",
    "puVar3": "srcPtr"
}

def main():
    # Find the function at the given address
    func = getFunctionAt(toAddr(FUNC_ADDR))
    if not func:
        print("Function not found at address: %s" % FUNC_ADDR)
        return

    # Rename the function to a more descriptive name
    func.setName(FUNC_NAME, SourceType.USER_DEFINED)
    print("Renamed function to: %s" % FUNC_NAME)

    # Rename the function parameters
    params = func.getParameters()
    if params:
        for i, param in enumerate(params):
            if param.getName() != "this" and param.getSource() == SourceType.USER_DEFINED:
                # Renaming only user-defined parameters, not auto parameters
                if i == 0:
                    param.setName("objectPtr", SourceType.USER_DEFINED)
                    print("Renamed first parameter to: objectPtr")
                elif i == 1:
                    param.setName("sourceData", SourceType.USER_DEFINED)
                    print("Renamed second parameter to: sourceData")
                elif i == 2:
                    param.setName("endPointer", SourceType.USER_DEFINED)
                    print("Renamed third parameter to: endPointer")

    # Decompile the function to rename local variables
    decompiled = decompileFunction(func)
    if decompiled is None:
        print("Failed to decompile function.")
        return

    # Rename local variables in the decompiled function
    variables = decompiled.getVariables()  # Corrected method to access local variables

    for variable in variables:
        old_name = variable.getName()
        if old_name in RENAME_LOCALS:
            new_name = RENAME_LOCALS[old_name]
            variable.setName(new_name, SourceType.USER_DEFINED)
            print("Renamed %s to %s" % (old_name, new_name))

def decompileFunction(func):
    # Initialize the decompiler interface
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    res = decompiler.decompileFunction(func, 60, monitor)
    if res and res.decompileCompleted():
        # Return the decompiled function directly
        return res.getDecompiledFunction()
    return None

main()