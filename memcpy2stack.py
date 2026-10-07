# Find memcpy calls that copy into stack buffers
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        currentProgram,
        getFunctionContaining,
        getReferencesTo,
        getSymbols,
        monitor,
    )
except ImportError:
    pass
from ghidra.app.decompiler import DecompInterface
import re

memcpy_symbol = getSymbols("memcpy", None)[0]
memcpy_refs = getReferencesTo(memcpy_symbol.address)

for ref in memcpy_refs:
  try:
      fn = getFunctionContaining(ref.fromAddress)
      decompInterface = DecompInterface()
      decompInterface.openProgram(currentProgram)
      res = decompInterface.decompileFunction(fn, 30, monitor)
      if res.decompileCompleted():
          decomp_fn = res.getDecompiledFunction()
          # check if decompiled code contains a stack buffer as input
          if re.search("memcpy\(.*?[sS]tack.*?,.*,", decomp_fn.getC()):
              print("memcpy with stack dst found near: {}"
                    .format(ref.fromAddress))
  except Exception as e:
      print("error:", e)

