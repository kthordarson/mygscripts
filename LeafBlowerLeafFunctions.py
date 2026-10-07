# Identify potential POSIX functions in the current program such as strcpy, strcat, memcpy, atoi, strlen, etc.

# @author kth
# @category mygscripts
# @menupath kthtools.Leaf Blower.Find leaf functions


try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from utils import leafblower

print ('Searching for potential POSIX leaf functions...')
leaf_finder = leafblower.LeafFunctionFinder(currentProgram)
leaf_finder.find_leaves()
leaf_finder.display()
