#Lists calling conventions
#@category Analysis
cc = currentProgram.getFunctionManager().getCallingConventionNames()
print("CONVENTIONS: " + ", ".join([str(c) for c in cc]))
print("DEFAULT: " + str(currentProgram.getCompilerSpec().getDefaultCallingConvention()))
print("COMPILERSPEC: " + str(currentProgram.getCompilerSpec().getCompilerSpecID()))
