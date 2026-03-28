# @author kth
# @category mygscripts
# BatchDecompile.py
# Decompile all functions in the current program and save them to a directory.

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import Function
import os

def run():
    if currentProgram is None:
        print("No program loaded!")
        return

    # Ask for output directory
    outDir = askDirectory("Select output directory", "OK")
    if outDir is None:
        print("No output directory selected.")
        return

    # Initialize decompiler
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    fm = currentProgram.getFunctionManager()
    count = 0

    for func in fm.getFunctions(True):
        try:
            results = decomp.decompileFunction(func, 60, monitor)
            if results and results.getDecompiledFunction():
                code = results.getDecompiledFunction().getC()
                fileName = func.getName() + ".c"
                filePath = os.path.join(outDir.getAbsolutePath(), fileName)
                with open(filePath, "w", encoding="utf-8") as f:
                    f.write(code)
                count += 1
        except Exception as e:
            print("Error decompiling {}: {}".format(func.getName(), e))

    print("Decompiled {} functions.".format(count))

run()