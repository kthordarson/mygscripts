# Find MIPS ROP gadgets that perform two controllable jumps.
# original author: fuzzywalls
# @author kth
# @category mygscripts
#@menupath TNS.Mips Rops.Gadgets.Double Jumps


try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

mips_rop = mipsrop.MipsRop(currentProgram)
doubles = mips_rop.find_doubles()

doubles.pretty_print()
