# Find MIPS ROP gadgets for calling system with a user controlled argument.
# original author: fuzzywalls
# @author kth
# @category mygscripts
#@menupath TNS.Mips Rops.Gadgets.System Calls


try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

set_a0 = mipsrop.MipsInstruction('.*addiu', 'a0', 'sp')

mips_rop = mipsrop.MipsRop(currentProgram)
system_rops = mips_rop.find_instructions([set_a0], 'a0',
                                         terminating_calls=False)

system_rops.pretty_print()
