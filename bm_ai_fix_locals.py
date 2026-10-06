#Correct params/types/locals on ai_remote_player_avoid_danger
#@category BM
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import PointerDataType, VoidDataType
US = SourceType.USER_DEFINED
prog = currentProgram
fm = prog.getFunctionManager()
rep = []
VOIDP = PointerDataType(VoidDataType.dataType)

f = fm.getFunctionAt(toAddr(0x0040b20f))

# 1) drop spurious trailing params, keep only param[0]
while f.getParameterCount() > 1:
    f.removeParameter(f.getParameterCount() - 1)
p0 = f.getParameter(0)
if p0 is not None:
    p0.setName("player", US)
    p0.setDataType(VOIDP, US)
    rep.append("param0 = %s %s" % (p0.getDataType().getDisplayName(), p0.getName()))

# 2) rename locals by CURRENT name (two-pass to avoid collisions)
final = {
 "local_3c":"playerCopy",
 "local_38":"moveDir",
 "local_34":"stepCount",
 "local_30":"dirIndex",
 "local_2c":"neighborCol",
 "local_28":"neighborRow",
 "playerCopy":"targetCol",
 "moveDir":"targetRow",
 "pathScratch":"result",
 "local_a0":"debugBuf",
}
allvars = list(f.getLocalVariables())
todo = []
for v in allvars:
    nm = v.getName()
    if nm in final:
        todo.append((v, final[nm]))

# pass 1: temp names
for i, (v, _) in enumerate(todo):
    try: v.setName("tmp_%d" % i, US)
    except Exception as e: rep.append("ERR tmp %s : %s" % (v.getName(), str(e)))
# pass 2: final names
for v, newname in todo:
    try:
        v.setName(newname, US)
        rep.append("loc -> %s" % newname)
    except Exception as e:
        rep.append("ERR final %s : %s" % (newname, str(e)))

# 3) retype the player-pointer local copy to void*
for v in f.getLocalVariables():
    if v.getName() == "playerCopy":
        try: v.setDataType(VOIDP, US)
        except Exception as e: rep.append("ERR retype playerCopy : %s" % str(e))

print("\n".join(rep))
