#@category GhidraScript
# Finds all functions that call FUN_00419110

from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import FunctionManager

# Function name to search for
target_function_name = "FUN_00419110"

def find_function_by_name(function_name):
    """Find function entry point by name"""
    function_manager = currentProgram.getFunctionManager()
    for function in function_manager.getFunctions(True):
        if function.getName() == function_name:
            return function
    return None

def find_callers(target_function):
    """Find all functions that call the target function"""
    if not target_function:
        print("Function {} not found!", target_function_name)
        return []
    
    callers = []
    refs = getReferencesTo(target_function.getEntryPoint())
    
    for ref in refs:
        if ref.getReferenceType().isCall():
            calling_function = getFunctionContaining(ref.getFromAddress())
            if calling_function and calling_function not in callers:
                callers.append(calling_function)
    
    return callers

def main(target_function_name):
    target_function = find_function_by_name(target_function_name)
    callers = find_callers(target_function)
    
    if callers:
        print("\nFunctions calling {}:", target_function_name)
        for caller in callers:
            print("- {} at {}", (caller.getName(), caller.getEntryPoint()))
    else:
        print("No functions call {}.", target_function_name)
target = 'CopyFunctionPointers'
main(target)
