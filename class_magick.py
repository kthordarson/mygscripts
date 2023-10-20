#Generate class structures based on vftable data
#@author buherator
#@category _NEW_
#@keybinding
#@menupath
#@toolbar

from ghidra.app.util import NamespaceUtils
from ghidra.program.model.data import Array, CategoryPath, PointerDataType, StructureDataType, DataTypeConflictHandler
from ghidra.program.model.listing import VariableUtilities, GhidraClass
from ghidra.program.model.symbol import SourceType
from ghidra.program.database.data import ArrayDB
from java.lang import ArrayIndexOutOfBoundsException

def createVftableType(namespace, length):
	dtm = currentProgram().getDataTypeManager()
	programName = getProgramFile().getName()
	categoryPath="/%s" % ('/'.join(namespace.getName(True).split("::")[:-1]))
	#category=dtm.createCategory(CategoryPath(categoryPath))
	structDataType=StructureDataType(CategoryPath(categoryPath), "%s_vftable" % namespace.getName(True).split('::')[-1], 0)
	dt=dtm.addDataType(structDataType, DataTypeConflictHandler.REPLACE_HANDLER)
	for i in range(0,length):
		p=PointerDataType()
		dt.add(p, currentProgram().getDefaultPointerSize(), "member%X" % (i),"")
	return dt

def createClassType(namespace, vftableDataType):
	dtm = currentProgram().getDataTypeManager()
	#structDataType=StructureDataType(CategoryPath(categoryPath), namespace.split('::')[-1], 0)
	p=PointerDataType(vftableDataType)
	structDataType = VariableUtilities.findOrCreateClassStruct(namespace, dtm)
	try:
		structDataType.getComponent(0)
		structDataType.replace(0, p, currentProgram().getDefaultPointerSize(), "fvtable","")
		return structDataType
	except ArrayIndexOutOfBoundsException:
		structDataType.add(p, currentProgram().getDefaultPointerSize(), "fvtable","")
		return dtm.addDataType(structDataType, DataTypeConflictHandler.REPLACE_HANDLER)

if __name__ == '__main__':
	currAddr = currentLocation().getAddress()
	originalData = getDataAt(currAddr)
	if originalData:
		try:
			originalDataType=originalData.getDataType()
		except AttributeError as e:
			print(f'[classmagic] err {e} ')
			exit()
	if not originalData:
		print("[!] originalData not found! currAddr "+str(currAddr))
		exit()
	if not originalDataType:
		print("[!] originalDataType not found! currAddr "+str(currAddr))
		exit()

	class_namespace=None
	symbol=None
	if originalData:
		symbol = originalData.getPrimarySymbol()
		if symbol:
			class_namespace = symbol.getParentNamespace()
		if not class_namespace:
			print("[!] Class namespace not found! symbol " + str(symbol) + " originalData " + str(type(originalData)))
			exit()

	newVftableDataType = None
	newClassDataType = None
	if originalDataType:
		print(f'originalDataType: {originalDataType} type: {type(originalDataType)} class_namespace: {class_namespace} {type(class_namespace)}')
		try:
			class_namespace = NamespaceUtils.convertNamespaceToClass(class_namespace)
		except Exception as e:
			print(f'[!] convertNamespaceToC {e} {type(e)} ')
		try:
			newVftableDataType = createVftableType(class_namespace, originalDataType.getNumComponents())
		except AttributeError as e:
			print(f'[!] {e} currAddr: {currAddr} ')
	if newVftableDataType:
		print(f'currAddr: {currAddr} class_namespace: {class_namespace} newVftableDataType: {newVftableDataType}')
		removeDataAt(currAddr)
		createData(currAddr, newVftableDataType)
		try:
			newClassDataType=createClassType(class_namespace, newVftableDataType)
		except TypeError as e:
			print(f'[E] TypeError {e} class_namespace={class_namespace} currAddr: {currAddr}')
			exit()
		for i in range(0,originalDataType.getNumComponents()*currentProgram().getDefaultPointerSize(), currentProgram().getDefaultPointerSize()):
			funcAddr=None
			# Ugly hack to get properly sized pointers
			if currentProgram().getDefaultPointerSize() == 4:
				funcAddrStr=hex(getInt(currAddr.add(i))).strip('L')
			if currentProgram().getDefaultPointerSize() == 8:
				funcAddrStr=hex(getLong(currAddr.add(i))).strip('L')
			funcAddr=getAddressFactory().getAddress(funcAddrStr)
			f=getFunctionAt(funcAddr)
			if f is not None:
				origName=f.getName()
				f.setParentNamespace(class_namespace)
			else:
				print(("[!] not a function at %x" % funcAddr.getOffset()))
