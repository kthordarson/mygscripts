from ghidra.program.model.data import StructureDataType, CategoryPath, DataTypeConflictHandler, PointerDataType, BuiltInDataTypeManager, ArrayDataType

class FoundVTable:
    def __init__(self, address, pointers=None):
        self.address = address
        if pointers is not None:
            self.pointers = pointers
        else:
            self.pointers = []
        self.associated_struct = None
    @property
    def size(self):
        return len(self.pointers)

    def __repr__(self):
        return "FoundVTable(address=%s, size=%d)" % (str(self.address), self.size)


bdm = BuiltInDataTypeManager.getDataTypeManager()
dm = currentProgram().getDataTypeManager()

