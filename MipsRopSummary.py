# Print a summary of ROP gadgets that are bookmarked with ropX.

# @author kth
# @category mygscripts
# @menupath kthtools.Mips Rops.Summary


try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from utils import mipsrop, utils

utils.allowed_processors(currentProgram, 'MIPS')

mips_rop = mipsrop.MipsRop(currentProgram)
mips_rop.summary()
