# Looks for matching libraries in current project and automatically assigns to current program.
# "Link existing project libraries" doesn't seem to fully work when using bulk import, and this
# pretty much reimplements this.
#
# After running this script you will probably want to use FixupELFExternalSymbolsScript.java too.
#
#@author infowski
#@category Symbol
#@keybinding F11
#@menupath
#@toolbar
import ghidra.framework.main
from ghidra.app.util import NamespaceUtils
from ghidra.program.model.data import Array, CategoryPath, PointerDataType, StructureDataType, DataTypeConflictHandler
from ghidra.program.model.listing import VariableUtilities, GhidraClass
from ghidra.program.model.symbol import SourceType

from ghidra.app.script import GhidraState
from ghidra.framework.model import *
from ghidra.program.database import ProgramContentHandler
from ghidra.program.model.listing import Program
from ghidra.util.exception import CancelledException
from ghidra.util.exception import VersionException

from ghidra.util.task import ConsoleTaskMonitor
from  ghidra.program.util import ExternalSymbolResolver

from loguru import logger


def findLibrary(name, base=None):
	if base is None:
		base = projdata.getRootFolder()

	for f in base.getFiles():
		if f.getName().startswith(name):
			return f

	for f in base.getFolders():
		tgt = findLibrary(name, f)
		if tgt:
			return tgt

	return None


if __name__=='__main__':
	project = state().getProject()
	projectData = project.getProjectData()
	rootFolder = projectData.getRootFolder()
	projdata = project.getProjectData() #ghidra.framework.main.AppInfo().getActiveProject().getProjectData()

	# exm = ghidra.framework.main.getState().currentProgram().getExternalManager()
	monitor = ConsoleTaskMonitor()
	exm = currentProgram().getExternalManager()# .getExternalLibrary(func.getExternalLocation().getLibraryName()).getAssociatedProgramPath()
	esr=ExternalSymbolResolver(projectData,monitor)
	# ExternalSymbolResolver.getLibrarySearchList(currentProgram)
	for lib in exm.getExternalLibraryNames():
		logger.debug(f'[lib] {lib}')
		if lib == '<EXTERNAL>': continue

		#print(lib, '->', exm.getExternalLibraryPath(lib))
		path = exm.getExternalLibraryPath(lib)
		if path is None:
			found = findLibrary(lib)
			if found:
				logger.info(f'Setting {lib} to {found.getPathname()}')
				exm.setExternalPath(lib, found.getPathname(), True)
