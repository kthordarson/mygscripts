# Find MIPS ROP gadgets that put a stack address in a register.

# @author kth
# @category mygscripts
# @menupath kthtools.Mips Rops.Gadgets.Stack Finder


try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

sf_saved_reg = mipsrop.MipsInstruction('.*addiu', '[sva][012345678]', 'sp')

mips_rop = mipsrop.MipsRop(currentProgram)
stack_finders = mips_rop.find_instructions([sf_saved_reg])

stack_finders.pretty_print()
