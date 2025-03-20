from ghidra.program.model.symbol import SourceType
import re
# rust-objdump.exe -d C:\temp\keystrike\keystrike-ssh-terminator --demangle > keysrtrikesshterminatordump.txt
# Path to rust-objdump output (adjust as needed)
objdump_file = "/path/to/keysrtrikesshterminatordump.txt"
objdump_file = 'c:/temp/keystrike/clientcab_fil0eIoBbEjF_M07WrvFDiNhbfiLVY.txt'
objdump_file = 'c:/temp/keystrike/clientcab_filB4nIvl6wWA1pFJiRAmgf_Aj1UVo.txt'
# Regex to match function lines (e.g., "00000000005ad870 <hyper::...>")
function_pattern = re.compile(r"([0-9a-f]{16}) <([^>]+)>:$")

# Read the objdump output
with open(objdump_file, "r") as f:
    lines = f.readlines()
    
for line in lines:
    match = function_pattern.match(line.strip())
    if match:
        address_str, function_name = match.groups()
        address = int(address_str, 16)  # Convert hex address to integer
        demangled_name = function_name.strip()        
        addr = toAddr(address) # Convert address to Ghidra Address object                 
        func = getFunctionAt(addr) # Check if a function exists at this address
        if func is None:
            # Create a new function if none exists
            createFunction(addr, demangled_name)
        else:            
            func.setName(demangled_name, SourceType.USER_DEFINED) # Rename existing function        
        print("Set function at 0x{} to '{}'".format(address_str, demangled_name))