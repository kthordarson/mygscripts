#funcrenamer
#@author kth
#@category Functions
#@keybinding
#@menupath Tools.funcren.funcren
#@toolbar
from loguru import logger
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.util.task import ConsoleTaskMonitor

from ghidra.app.util import NamespaceUtils
from ghidra.program.model.data import Array, CategoryPath, PointerDataType, StructureDataType, DataTypeConflictHandler
from ghidra.program.model.listing import VariableUtilities, GhidraClass
from ghidra.program.model.symbol import SourceType
from java.lang import ArrayIndexOutOfBoundsException

INTERESTING_FUNCS = ['CreateWindowExA',	'printf', 'DrawTextA', 'MessageBoxA', 'ShellExecuteA', 'SetDlgItemTextA', 'CreateFontA', 'CreateFileA',	'icf_port_strcpy',]

def get_func_parameters(func):
	pass

def get_funclist(prefix='FUN_'):
	funcList = [f for f in currentProgram().getListing().getFunctions(True) if prefix in f.getName()]
	# funcList = [f for f in currentProgram().getListing().getFunctions(True)]
	# logFuncs = [f for f in currentProgram().getListing().getFunctions(True) if 'log' in str(f.getName()).lower()]
	# logFunc = [f for f in currentProgram().getListing().getFunctions(True) if 'zySyslog' in f.getName()][0]
	# dbgFunc = [f for f in currentProgram().getListing().getFunctions(True) if 'tcdbg_printf' in f.getName()][0]

	monitor = ConsoleTaskMonitor()
	result = []
	for idx,func in enumerate(funcList):
		curParentNodes = [(k, k.getName()) for k in func.getCallingFunctions(monitor)]
		called_functions = func.getCalledFunctions(monitor)
		called_function_names = [cf.getName() for cf in called_functions]
		ifuncs = [cf for cf in called_functions if cf.getName() in INTERESTING_FUNCS] # check these function parameters for interesting strings
		if len(ifuncs)>0:
			#logger.debug(f'[fr] idx={idx} addr={func.getEntryPoint()} name={func.getName()} icalls={len(ifuncs)}')
			result.append({
				'idx': idx,
				'func' : func,
				'func_entryp': func.getEntryPoint(),
				'func_name' : func.getName(),
				'called_function_names': called_function_names,
				'func_calls': called_functions,
				'curParentNodes':curParentNodes,
				'ifuncs': ifuncs })
	logger.info(f'[fr] found {len(funcList)} funcs res={len(result)}')
	return result

if __name__ == '__main__':
	logger.info('[funcren] start')

	fl = get_funclist()
	for f in fl:
		logger.debug(f'[funcren] idx:{f.get("idx")} name:{f.get("func_name")} func_calls:{len(f.get("func_calls"))} called_function_names: {f.get("called_function_names")} curParentNodes:{len(f.get("curParentNodes"))}')
