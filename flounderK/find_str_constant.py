# Find functions using the 0x80808080 constant typical of optimized string routines
# @author kth
# @category mygscripts

try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from ghidra_api.decomp_utils import DecompUtils

du = DecompUtils()

for func in currentProgram.getFunctionManager().getFunctions(1):
    if func.isThunk() or func.isExternal():
        continue
    pcode_ops = du.get_pcode_for_function(func)
    if not pcode_ops:
        continue

    for op in pcode_ops:
        next_fn = False
        for vn in op.getInputs():
            if not vn.isConstant() and not vn.isAddress():
                continue
            if vn.getOffset() in [0x80808080, 0x8080808080808080]:
                next_fn = True
                print("%s: %s" % (str(func), op.seqnum.getTarget()))
                break
        if next_fn:
            break

