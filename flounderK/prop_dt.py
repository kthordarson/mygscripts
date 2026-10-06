# naively propagate a datatype forward to all function signatures it directly
# flows to
# @author kth
# @category mygscripts


try:
    from ghidra.ghidra_builtins import (
        askInt,
        askString,
        currentProgram,
        currentSelection,
        getFunction,
        getFunctionContaining,
    )
except ImportError:
    pass
from type_propagator import prop_datatype_from_func_param
from ghidra_api.decomp_utils import DecompUtils


selection = currentSelection

if selection:
    addr = selection.minAddress
    func = getFunctionContaining(addr)
else:
    func_name = askString("enter function name", "enter function name")
    func = getFunction(func_name)

param_num = askInt("Parameter (indexed from 1)", "Parameter (indexed from 1)")

prop_datatype_from_func_param(func, param_num, program=currentProgram)
