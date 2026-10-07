# Fix overlapping 0x2c/0x2e direction fields in GamePlayer
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from ghidra.program.model.data import ShortDataType
from java.util import ArrayList

prog = currentProgram
dtm = prog.getDataTypeManager()
SHORT = ShortDataType.dataType
al = ArrayList()
dtm.findDataTypes("GamePlayer", al)
gp = al.get(0)
# clear any component spanning 0x2c..0x2f then set two shorts
try:
    gp.clearAtOffset(0x2C)
except Exception as e:
    pass
gp.replaceAtOffset(
    0x2C, SHORT, 2, "moveDir", "committed direction (low word of 0x2c dword)"
)
gp.replaceAtOffset(
    0x2E, SHORT, 2, "requestedDir", "requested direction; -1/0xffff = none, &3 = dir"
)
c2c = gp.getComponentAt(0x2C)
c2e = gp.getComponentAt(0x2E)
print("0x2c -> %s %s" % (c2c.getDataType().getName(), c2c.getFieldName()))
print("0x2e -> %s %s" % (c2e.getDataType().getName(), c2e.getFieldName()))
print("size = 0x%x" % gp.getLength())
