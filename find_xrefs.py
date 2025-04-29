# Who reference this function( (target_function_name)
#
# @category xref.Demo
#

# Import libraries from Ghidra that will be available to use.
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.program.model.listing import Function
from java.util import HashSet

# Function to find all callers recursively
def find_callers(function, visited, path, all_paths):
    references = program.getReferenceManager().getReferencesTo(function.getEntryPoint())
    found_new_caller = False
    for ref in references:
        if ref.getReferenceType().isCall():
            caller = function_manager.getFunctionContaining(ref.getFromAddress())
            if caller and caller not in visited:
                visited.add(caller)
                path.append(caller.getName())
                find_callers(caller, visited, path, all_paths)
                path.pop()
                found_new_caller = True
    if not found_new_caller:
        all_paths.append(list(path))  # Add a copy of the current path

# target_function_name = "main"
target_function_name = "FUN_014a6bb0"
        
print("~~~~~~~~~~~~~~~~Start of script~~~~~~~~~~~~~~~~")
program = getCurrentProgram()
listing = program.getListing()
monitor = ConsoleTaskMonitor()

function_manager = program.getFunctionManager()
functions = function_manager.getFunctions(True)  # True to iterate forward through functions

# Find the target function
target_function = None
for function in functions:
    if function.getName() == target_function_name:
        target_function = function
        break

if not target_function:
    print("Function '{}' not found.".format(target_function_name))
else:
    print("Building call paths to '{}'...".format(target_function_name))
    visited = HashSet()  # Track visited functions to prevent cycles
    visited.add(target_function)
    all_paths = []
    find_callers(target_function, visited, [target_function.getName()], all_paths)
    
    print("All paths leading to '{}':".format(target_function_name))
    for path in all_paths:
        print(" -> ".join(reversed(path)))

print("~~~~~~~~~~~~~~~~~End of script~~~~~~~~~~~~~~~~~")