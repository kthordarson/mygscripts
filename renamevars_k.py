# Script requests current variable name and desired new name.
# It then iterates through all functions, renaming the variable.
# @author kth
# @category mygscripts
#
# Note: Script does not verify that no other variable within the
#       function is already using the new name.
#

try:
	from ghidra.ghidra_builtins import (
		currentProgram,
		monitor,
	)
except ImportError:
	pass
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SourceType
from ghidra.framework.model import DomainFile
from ghidra.framework.model import DomainFolder
from ghidra.program.model.address import Address
from ghidra.program.model.lang import LanguageCompilerSpecPair
from ghidra.program.model.listing import Program
from ghidra.util import Msg

from java.lang import IllegalArgumentException
from ghidra.util.exception import CancelledException


def rename_variable():
	# Get current variable name
	cur_name = 'param_2'  # askString("Current variable name", "Current Name")
	if cur_name is None:
		return

	# Get desired new variable name
	new_name = 'lsmsg'  # askString("New variable name", "New Name")
	if new_name is None:
		return

	# Initialize count and get function iterator
	count = 0
	funcs = currentProgram().getListing().getFunctions(True)

	# Iterate through all functions in current program's listing
	while funcs.hasNext() and not monitor().isCancelled():
		# Get current function and list of associated variables
		f = funcs.next()
		vars = f.getLocalVariables()

		# Iterate through all variables for current function
		for v in vars:
			if v.getName() == cur_name:
				print(f"{f.getName()}::{v.getName()}")
				v.setName(new_name, SourceType.USER_DEFINED)
				count += 1

	print(f"Found {count} instances of {cur_name}")

if __name__ == "__main__":
	# Run the rename_variable function
	rename_variable()
