#Retype ai_remote_player_avoid_danger param to GamePlayer* now that struct is 0x98
#@category BM
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.symbol import SourceType
from java.util import ArrayList
US = SourceType.USER_DEFINED
prog = currentProgram
dtm = prog.getDataTypeManager()
fm = prog.getFunctionManager()
al = ArrayList(); dtm.findDataTypes("GamePlayer", al)
gpp = PointerDataType(al.get(0))
f = fm.getFunctionAt(toAddr(0x0040b20f))
p = f.getParameter(0)
p.setName("player", US)
p.setDataType(gpp, US)
print("param0 = %s %s" % (p.getDataType().getDisplayName(), p.getName()))
