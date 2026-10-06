#Rename+fixup FUN_0040b20f (remote-player danger-avoidance AI) and its callees
#@category BM
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import IntegerDataType, PointerDataType, VoidDataType
from java.util import ArrayList
US = SourceType.USER_DEFINED
prog = currentProgram
fm = prog.getFunctionManager()
dtm = prog.getDataTypeManager()
rep = []

INT = IntegerDataType.dataType

def find_type(name):
    lst = ArrayList()
    dtm.findDataTypes(name, lst)
    return lst.get(0) if lst.size() > 0 else None

def set_cc(addr, cc):
    f = fm.getFunctionAt(toAddr(addr))
    if f is None:
        rep.append("MISS cc %x" % addr); return None
    try:
        f.setCallingConvention(cc)
        rep.append("CC  %s -> %s" % (f.getName(), cc))
    except Exception as e:
        rep.append("ERR cc %x : %s" % (addr, str(e)))
    return f

set_cc(0x00424d37, "__regparm2")   # get_board_overlay_value_at_tile(col@EAX,row@EDX)
set_cc(0x0040a59d, "__regparm2")   # is_tile_free_for_placement(col@EAX,row@EDX)
set_cc(0x0040a76e, "__regparm1")   # cancel_remote_player_movement_if_blocked(player@EAX)

f = set_cc(0x0040b20f, "__regparm1")
if f is not None:
    try: f.setName("ai_remote_player_avoid_danger", US)
    except Exception as e: rep.append("ERR name : %s" % str(e))
    try: f.setReturnType(INT, US)
    except Exception as e: rep.append("ERR ret : %s" % str(e))

    gp_base = find_type("GamePlayer")
    gp = PointerDataType(gp_base) if gp_base is not None else PointerDataType(VoidDataType.dataType)
    ps = f.getParameters()
    if len(ps) >= 1:
        try:
            ps[0].setName("player", US)
            ps[0].setDataType(gp, US)
            rep.append("PARM player : %s" % ps[0].getDataType().getDisplayName())
        except Exception as e:
            rep.append("ERR parm : %s" % str(e))
    else:
        rep.append("WARN no params returned (spilled?)")

    names = {-0x20:"moveDir", -0x1c:"pathScratch", -0x18:"dirIndex",
             -0x14:"neighborCol", -0x10:"neighborRow", -0xc:"targetCol",
             -0x8:"targetRow", -0x4:"result", -0x88:"debugBuf", -0x24:"playerCopy"}
    for v in f.getStackFrame().getStackVariables():
        off = v.getStackOffset()
        if off in names:
            try:
                v.setName(names[off], US)
                rep.append("LOC %+#x -> %s" % (off, names[off]))
            except Exception as e:
                rep.append("ERR loc %+#x : %s" % (off, str(e)))

print("\n".join(rep))
