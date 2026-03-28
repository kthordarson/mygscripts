# Save as export_symbols.py in Ghidra's script directory
from ghidra.program.model.symbol import SymbolType
output_file = "/home/kth/Games/atomiciso/bm95exesymbols.r2"
symbolnames = [symbol.getName() for symbol in currentProgram().getSymbolTable().getAllSymbols(True)]
afnsymbolnames = [symbol.getName() for symbol in currentProgram().getSymbolTable().getAllSymbols(True) if symbol.getSymbolType() == SymbolType.FUNCTION]
labelsymbolnames = [symbol.getName() for symbol in currentProgram().getSymbolTable().getAllSymbols(True) if symbol.getSymbolType() == SymbolType.FUNCTION]

r2commands = []
afn_commands = [f'afn {symbol.getName()} @ {symbol.getAddress()}' for symbol in currentProgram().getSymbolTable().getAllSymbols(True) if symbol.getSymbolType() == SymbolType.FUNCTION]
label_commands = [f'f {symbol.getName()} @ {symbol.getAddress()}' for symbol in currentProgram().getSymbolTable().getAllSymbols(True) if symbol.getSymbolType() == SymbolType.LABEL]
r2commands.extend(afn_commands)
r2commands.extend(label_commands)
with open(output_file, "w") as f:
	for command in r2commands:
		f.write(command + "\n")
# with open(output_file, "w") as f:
#     for symbol in currentProgram().getSymbolTable().getAllSymbols(True):
#         if symbol.getSymbolType() == SymbolType.FUNCTION:
#             f.write(f"afn {symbol.getName()} @ {symbol.getAddress()}\n")
#         elif symbol.getSymbolType() == SymbolType.LABEL:
#             f.write(f"f {symbol.getName()} @ {symbol.getAddress()}\n")
# print(f"Symbols exported to {output_file}")
