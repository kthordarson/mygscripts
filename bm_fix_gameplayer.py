#Rebuild GamePlayer (0x98) with verified fields, define g_players[10], fix conventions
#@category BM
from ghidra.program.model.data import (StructureDataType, ByteDataType, IntegerDataType,
    ShortDataType, ArrayDataType, CategoryPath, PointerDataType)
from ghidra.program.model.symbol import SourceType
from java.util import ArrayList
US = SourceType.USER_DEFINED
prog = currentProgram
dtm = prog.getDataTypeManager()
fm = prog.getFunctionManager()
rep = []

BYTE = ByteDataType.dataType
INT = IntegerDataType.dataType
SHORT = ShortDataType.dataType

# locate existing GamePlayer
al = ArrayList(); dtm.findDataTypes("GamePlayer", al)
if al.size() == 0:
    print("GamePlayer not found"); 
else:
    old = al.get(0)
    cat = old.getCategoryPath()
    new = StructureDataType(cat, "GamePlayer", 0x98, dtm)
    fields = [
        (0x00, INT,  "moveState"),
        (0x04, INT,  "moveSubState"),
        (0x08, INT,  "isMoving"),
        (0x10, BYTE, "controlType"),      # 0=none,1=human/local,4=?
        (0x14, INT,  "pixelX"),
        (0x18, INT,  "pixelY"),
        (0x1c, INT,  "curPixelX"),
        (0x20, INT,  "curPixelY"),
        (0x2c, INT,  "moveDirFixed"),     # >>16 == -1 => none; low word = dir
        (0x2e, SHORT,"requestedDir"),
        (0x30, SHORT,"tileCol"),
        (0x32, SHORT,"tileStep"),
        (0x36, BYTE, "btnBombPrev"),
        (0x37, BYTE, "btnActionPrev"),
        (0x38, BYTE, "btnBomb"),
        (0x39, BYTE, "btnAction"),
        (0x3a, SHORT,"inputTimer"),
        (0x3c, INT,  "spriteState"),
        (0x4e, SHORT,"aiActionState"),
        (0x50, SHORT,"aiActionSub"),
        (0x54, BYTE, "playerNumber"),
        (0x66, SHORT,"bombTimer"),
        (0x68, BYTE, "queuedBombs"),
        (0x74, INT,  "moveAccum"),
        (0x78, INT,  "slideTimer"),
        (0x7c, INT,  "slideThreshold"),
        (0x80, INT,  "diseaseTimer"),
        (0x84, ArrayDataType(BYTE, 14, 1), "powerupFlags"),
        (0x92, BYTE, "aiMoveLatch"),
        (0x94, INT,  "showDebugInfo"),
    ]
    for off, dt, nm in fields:
        try:
            new.replaceAtOffset(off, dt, dt.getLength(), nm, None)
        except Exception as e:
            rep.append("ERR field %s@%#x : %s" % (nm, off, str(e)))
    try:
        old.replaceWith(new)
        rep.append("GamePlayer rebuilt: size=0x%x" % old.getLength())
    except Exception as e:
        rep.append("ERR replaceWith : %s" % str(e))

    # g_players[10] @ 0x461bc4
    try:
        base = toAddr(0x00461bc4)
        arr = ArrayDataType(old, 10, old.getLength())
        clearListing(base, toAddr(0x00461bc4 + 10*0x98 - 1))
        createData(base, arr)
        createLabel(base, "g_players", True, US)
        rep.append("g_players[10] @ 461bc4 (%d bytes)" % (10*0x98))
    except Exception as e:
        rep.append("ERR g_players : %s" % str(e))

# conventions + param names
def fixfn(addr, cc, params):
    f = fm.getFunctionAt(toAddr(addr))
    if f is None:
        rep.append("MISS fn %x" % addr); return
    try:
        f.setCallingConvention(cc)
        ps = f.getParameters()
        for i,(nm,tp) in enumerate(params):
            if i < len(ps):
                ps[i].setName(nm, US)
                if tp is not None: ps[i].setDataType(tp, US)
        rep.append("FN  %s -> %s" % (f.getName(), cc))
    except Exception as e:
        rep.append("ERR fn %x : %s" % (addr, str(e)))

gp_ptr = PointerDataType(al.get(0)) if al.size() > 0 else None
fixfn(0x0040a1c6, "__regparm2", [("playerIndex", INT), ("player", gp_ptr)])
fixfn(0x0041f29b, "__regparm1", [("player", gp_ptr)])

print("\n".join(rep))
