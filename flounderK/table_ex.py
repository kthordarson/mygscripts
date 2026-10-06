# Example of a TableChooserDialog with custom columns under PyGhidra
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
    )
except ImportError:
    pass

from jpype import JImplements, JOverride, JClass
from ghidra.app.tablechooser import TableChooserExecutor
from ghidra.app.tablechooser import AddressableRowObject
from ghidra.app.tablechooser import ColumnDisplay

# PyGhidra (JPype) cannot subclass Java classes, only implement Java
# interfaces via @JImplements / @JOverride.


@JImplements(AddressableRowObject)
class QuickRow(object):
    def __init__(self, address):
        self._address = address
        self.fields = {}

    @JOverride
    def getAddress(self):
        return self._address

    @property
    def address(self):
        return self._address

    @staticmethod
    def create(address, **kwargs):
        row = QuickRow(address)
        for k, v in kwargs.items():
            row.fields[k] = v
        return row


@JImplements(ColumnDisplay)
class ValColumn(object):
    def __init__(self, name):
        self.name = name

    @JOverride
    def getColumnValue(self, row):
        val = row.fields.get(self.name)
        return None if val is None else str(val)

    @JOverride
    def getColumnName(self):
        return self.name

    @JOverride
    def getColumnClass(self):
        return JClass("java.lang.String").class_

    @JOverride
    def compare(self, o1, o2):
        v1 = str(self.getColumnValue(o1))
        v2 = str(self.getColumnValue(o2))
        return (v1 > v2) - (v1 < v2)

    # Comparator re-declares equals() abstractly, so JPype requires it
    @JOverride
    def equals(self, other):
        return self is other


def new_column(name):
    return ValColumn(name)


@JImplements(TableChooserExecutor)
class TabEx(object):
    @JOverride
    def getButtonName(self):
        return "apply"

    @JOverride
    def execute(self, rowObj):
        # return True to remove the row from the table after execution
        return False


executor = TabEx()
dialog = createTableChooserDialog("name", executor, True)
dialog.addCustomColumn(new_column("Value"))
dialog.addCustomColumn(new_column("Description"))
dialog.add(QuickRow.create(toAddr(1), Value=1, Description="blah"))
dialog.show()
