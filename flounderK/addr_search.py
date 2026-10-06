# Search the address space of the current program for a pointer
# @author kth
# @category mygscripts

try:
	from ghidra.ghidra_builtins import (
		createTableChooserDialog,
		currentProgram,
		getFunctionContaining,
		getMemoryBlocks,
		state,
		toAddr,
		monitor,
		getFunctionAt,
		createFunction,
		findBytes,
		askAddress
	)
except ImportError:
	pass
from ghidra.program.model.symbol import SourceType
from ghidra_api.pointer_utils import createPointerUtils
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

selection = state.currentSelection
if selection is None:
	log.debug("No selection detected, asking for address")
	addr = askAddress("Address to search for", "Enter address to search for")
else:
	addr = selection.minAddress

log.info("[+] Searching for %s", addr)

ptr_util = createPointerUtils()

match_addrs = ptr_util.search_for_pointer(addr)
for addr in match_addrs:
	print("%s" % addr)
