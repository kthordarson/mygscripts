# Ghidra Python script to demangle Microsoft C++ symbols (including Qt and RTTI)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.app.util.demangler import DemanglerUtil

def demangle_symbols():
    # Get the current program
    program = currentProgram
    symbol_table = program.getSymbolTable()
    
    # Counter for processed symbols
    count = 0
    
    # Iterate through all symbols in the program
    # symbols = [k for k in symbol_table.getAllSymbols(True)]
    symbols = [k for k in symbol_table.getAllSymbols(True) if k.getName().startswith("?") and k.isGlobal()]
    print("Processing {} symbols".format(len(symbols)))
    for symbol in symbols:
        mangled_name = symbol.getName()
        address = symbol.getAddress()
        
        try:
            # Use DemanglerUtil.demangle directly
            demangled = DemanglerUtil.demangle(program, mangled_name)
            
            if demangled is not None:
                # Get the demangled name
                demangled_name_signature = demangled.getSignature()
                
                # Clean up the name (remove extra spaces and qualifiers if desired)
                demangled_name = str(demangled_name_signature.replace(" __cdecl ", " ")).replace(' ','')
                
                # Apply the demangled name to the symbol
                symbol_table.createLabel(address, demangled_name, True, SourceType.ANALYSIS)
                print("Demangled {} -> {}".format(mangled_name, demangled_name))
                count += 1
            else:
                print("Could not demangle {} at {} demangled: {}".format(mangled_name, address,demangled))
                
        except Exception as e:
            pass  # print("Failed to demangle {}: {}".format(mangled_name, str(e)))
            continue
    
    print("Processed {} symbols".format(count))

if __name__ == "__main__":
    demangle_symbols()