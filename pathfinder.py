# Search for call paths between two functions in the current program.
# @author kth
# @category mygscripts

try:
	from ghidra.ghidra_builtins import (
		askString,
		currentProgram,
		getSymbol,
		monitor,
	)
except ImportError:
	pass
from ghidra.app.util.bin import ByteProvider, RandomAccessByteProvider, BinaryReader
from ghidra.program.model.symbol import RefType
from ghidra.program.model.address import AddressFormatException
import itertools

global_namespace = currentProgram.getNamespaceManager().getGlobalNamespace()
listing = currentProgram.getListing()
symbols = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()
af = currentProgram.getAddressFactory()

def memoize(func):
	cache = dict()

	def memoized_func(*args):
		if args in cache:
			return cache[args]
		result = func(*args)
		cache[args] = result
		return result
	return memoized_func

def group(iterator, n):
	while True:
		chunk = tuple(itertools.islice(iterator, n))
		if not chunk:
			return
		yield chunk

@memoize
def who_calls(symbol):
	valid_types = [RefType.UNCONDITIONAL_CALL, RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL, RefType.CONDITIONAL_COMPUTED_CALL]
	refs = filter(lambda x: x.getReferenceType() in valid_types, symbol.getReferences())
	callers = []
	for ref in refs:
		caller_func = listing.getFunctionContaining(ref.getFromAddress())
		if caller_func:
			callers.append(caller_func.getSymbol())
	return callers

def find_function(identifier):
	"""
	Finds a function by address (hex string), name, label, or mangled name.

	:param program: The current Ghidra program object.
	:param identifier: String representing address, name, or mangled name.
	:return: Function object or None if not found.
	"""
	# fm = program.getFunctionManager()
	# st = program.getSymbolTable()
	# af = program.getAddressFactory()

	# 1. Try to treat identifier as an Address (e.g., "0x00401234")
	try:
		addr = af.getAddress(identifier)
		if addr:
			# getFunctionAt only finds if addr is the entry point
			# getFunctionContaining finds it even if addr is inside the body
			func = fm.getFunctionContaining(addr)
			if func:
				return func
	except AddressFormatException:
		# Not a valid address string, move on to symbol search
		pass

	# 2. Search for the identifier as a Symbol (Name, Label, or Mangled)
	# This returns an iterator of symbols matching the string
	symbols = symbols.getSymbols(identifier)

	for sym in symbols:
		# Ensure the symbol actually points to a function
		# (This filters out labels on data or external constants)
		if sym.getSymbolType().toString() == "Function":
			return sym.getObject()

	return None

# Example Usage:
# func = find_function(currentProgram, "0x00101230")
# func = find_function(currentProgram, "_ZN7Example4testEv")
# func = find_function(currentProgram, "main")
def ask_symbol(title, message):
	sym = None
	while sym is None:
		user_input = askString(title, message)
		if not user_input:
			return None

		# Try exact match first
		sym = getSymbol(user_input, global_namespace)

		# If no exact match, search all symbols by demangled name
		if sym is None:
			for symbol in symbols.getAllSymbols(True):
				if symbol.getName() == user_input or symbol.getName(True) == user_input:
					sym = symbol
					break
		if sym is None:
			sym = find_function(user_input)
		if sym is None:
			print("Symbol '{}' not found. Try again.".format(user_input))

	return sym

def old_ask_symbol(title, message):
	sym = None
	while sym is None:
		# sym = symbols.getSymbol(askString(title, message))
		sym = getSymbol(askString(title, message), global_namespace)
		# symbols.getSymbol(0x01747db,'net_send',namespace)
	return sym

def find_bfs(start_func, stop_func):
	visited = [start_func]
	queue = [[start_func]]

	while queue:
		path = queue.pop(0)
		func = path[-1]

		if func == stop_func:
			yield path

		for caller in who_calls(func):
			# Change path to visited to prevent loops globally, not just in the current path.
			# Can be useful when you only want the shortest path for each tree.
			if caller not in path:
				visited.append(caller)
				new_path = list(path)
				new_path.append(caller)
				queue.append(new_path)


def run_find_bfs(src_func, dst_func, max_paths=100):
	path_count = 0
	s = ''
	el = ''
	seen_paths = set()
	for path in find_bfs(dst_func, src_func):
		# print("Path({}):".format(len(path)))
		first = True
		for el in group(reversed(path), 20):
			# print("el: {}".format(el))
			if el not in seen_paths:
				s = " -> ".join([str(x) for x in el])
				print("\t{} {} {}".format("-> " if not first else " ", path_count,s))
				first = False
				monitor.checkCanceled()
				seen_paths.add(s)
		path_count += 1
		if len(seen_paths) >= max_paths:
			print("Reached maximum path count of {}, stopping. seen_paths: {}".format(max_paths, len(seen_paths)))
			# print("last path: ".format(path))
			break
def run_find_bfs_shortest(src_func, dst_func):
	for path in find_bfs(dst_func, src_func):
		print("Path({}):".format(len(path)))
		first = True
		for el in group(reversed(path), 20):
			s = " -> ".join([str(x) for x in el])
			print("\t{}{}".format("-> " if not first else "", s))
			first = False
			monitor.checkCanceled()
		return  # Exit after first path found

def old_find_bfs(start_func, stop_func):
	visited = [start_func]
	queue = [[start_func]]

	while queue:
		monitor.checkCanceled()
		path = queue.pop(0)
		func = path[-1]

		if func == stop_func:
			yield path

		for caller in who_calls(func):
			# Change path to visited to prevent loops globally, not just in the current path.
			# Can be useful when you only want the shortest path for each tree.
			if caller not in path:
				visited.append(caller)
				new_path = list(path)
				new_path.append(caller)
				queue.append(new_path)

def test_two(dst_func, src_func):
	for path in old_find_bfs(dst_func, src_func):
		print("Path({}):".format(len(path)))
		first = True
		for el in group(reversed(path), 20):
			s = "[*] -> ".join([str(x) for x in el])
			print("\t{}{}".format("-> " if not first else "", s))
			first = False
			monitor.checkCanceled()

def main():
	src_func = ask_symbol("Source Function", "Source function name?")
	dst_func = ask_symbol("Destination Function", "Destination function name?")
	run_find_bfs(src_func, dst_func)
	run_find_bfs_shortest(src_func, dst_func)
	# test_two(dst_func, src_func)

if __name__ == "__main__":
	main()
