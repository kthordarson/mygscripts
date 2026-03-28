from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Function
from ghidra.program.model.address import AddressFactory

# Get the Program object by calling currentProgram()
program = currentProgram()
if program is None:
    print("No program is open in the CodeBrowser. Please open a program and try again.")
    exit()

# Get the function at address 00425495 (compare_and_offset_string)
address = program.getAddressFactory().getAddress("00425495")
function = program.getFunctionManager().getFunctionAt(address)
if function is None:
    print("Function at address 00425495 (compare_and_offset_string) not found!")
    exit()

# Rename the function to AdjustSourcePath (optional)
if function.getName() != "AdjustSourcePath":
    function.setName("AdjustSourcePath", SourceType.USER_DEFINED)
    print("Renamed function at 00425495 to AdjustSourcePath")

# Parameter names to propagate
param_names = ["errorInfo", "sourceFile", "lineNumber"]

# Find references to the function
refs = getReferencesTo(address)
for ref in refs:
    caller = getFunctionContaining(ref.getFromAddress())
    if caller:
        print(f"Processing caller: {caller.getName()}")
        params = caller.getParameters()
        for i, param in enumerate(params):
            if i < len(param_names):
                param.setName(param_names[i], SourceType.USER_DEFINED)
                print(f"Renamed parameter {i} in {caller.getName()} to {param_names[i]}")

# Rename globals
globals_to_rename = {"s_C:\\projects\\AMMYY\\sources_004a4d30": "ammySourcePath"}
for old_name, new_name in globals_to_rename.items():
    g_address = program.getAddressFactory().getAddress("004a4d30")
    g_symbol = program.getSymbolTable().getPrimarySymbol(g_address)
    if g_symbol:
        g_symbol.setName(new_name, SourceType.USER_DEFINED)
        print(f"Renamed global {old_name} to {new_name}")

print("Done!")