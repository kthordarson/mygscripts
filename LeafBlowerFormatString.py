# Identify potential POSIX functions in the current program such as sprintf, fprintf, sscanf, etc.
# original author: fuzzywalls
# @author kth
# @category mygscripts
#@menupath TNS.Leaf Blower.Find format string functions


try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from utils import leafblower

print ('Searching for format string functions...')
format_string_finder = leafblower.FormatStringFunctionFinder(currentProgram)
format_string_finder.find_functions()
format_string_finder.display()
