# Lists calling conventions
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
cc = currentProgram.getFunctionManager().getCallingConventionNames()
print("CONVENTIONS: " + ", ".join([str(c) for c in cc]))
print("DEFAULT: " + str(currentProgram.getCompilerSpec().getDefaultCallingConvention()))
print("COMPILERSPEC: " + str(currentProgram.getCompilerSpec().getCompilerSpecID()))
