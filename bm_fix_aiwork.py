# Define AiWorkEntry (0x44) and retype g_currentRemotePlayer / g_aiWorkBuffer
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        clearListing,
        createData,
        currentProgram,
        getDataAt,
    )
except ImportError:
    pass
from ghidra.program.model.data import (
    StructureDataType,
    ShortDataType,
    CategoryPath,
    PointerDataType,
    ArrayDataType,
)
from ghidra.program.model.symbol import SourceType
from java.util import ArrayList

US = SourceType.USER_DEFINED
prog = currentProgram
dtm = prog.getDataTypeManager()
st = prog.getSymbolTable()
SHORT = ShortDataType.dataType
rep = []

# 1) build AiWorkEntry (0x44 bytes)
awe = StructureDataType(CategoryPath("/Copilot"), "AiWorkEntry", 0x44, dtm)
fields = [
    (0x00, "personality", "0 = default personality callback list"),
    (0x02, "pathActive", "1 = currently pathing to a target tile"),
    (0x04, "targetCol", None),
    (0x06, "targetRow", None),
    (0x08, "targetCost", "cached board-overlay value of target tile"),
    (0x28, "subTileX", "pixel_x_to_tile_center_offset"),
    (0x2A, "subTileY", "pixel_y_to_tile_bottom_offset"),
    (0x2C, "dirOffsetX", "direction-rotated sub-tile offset"),
    (0x2E, "dirOffsetY", None),
    (0x30, "curTileCol", "current tile column"),
    (0x32, "curTileRow", "current tile row"),
]
for off, nm, cmt in fields:
    try:
        awe.replaceAtOffset(off, SHORT, 2, nm, cmt)
    except Exception as e:
        rep.append("ERR field %s@%#x : %s" % (nm, off, str(e)))

# resolve/add into the program's DTM
al = ArrayList()
dtm.findDataTypes("AiWorkEntry", al)
if al.size() > 0:
    existing = al.get(0)
    try:
        existing.replaceWith(awe)
        awe = existing
        rep.append("AiWorkEntry replaced (size 0x%x)" % awe.getLength())
    except Exception as e:
        rep.append("ERR replaceWith : %s" % str(e))
else:
    awe = dtm.addDataType(awe, None)
    rep.append("AiWorkEntry created (size 0x%x)" % awe.getLength())

AWEP = PointerDataType(awe)


# 2) retype g_currentRemotePlayer -> AiWorkEntry*
def sym_addr(name):
    it = st.getGlobalSymbols(name)
    return it[0].getAddress() if len(it) > 0 else None


a = sym_addr("g_currentRemotePlayer")
if a is not None:
    try:
        clearListing(a, a.add(3))
        createData(a, AWEP)
        rep.append("g_currentRemotePlayer @ %s -> AiWorkEntry *" % a)
    except Exception as e:
        rep.append("ERR retype g_currentRemotePlayer : %s" % str(e))
else:
    rep.append("g_currentRemotePlayer symbol not found")

# 3) g_aiWorkBuffer -> AiWorkEntry[10] (if it's the array base, not a pointer)
b = sym_addr("g_aiWorkBuffer")
if b is not None:
    d = getDataAt(b)
    tname = d.getDataType().getName() if d else "<undef>"
    rep.append("g_aiWorkBuffer @ %s current=%s" % (b, tname))
    # only redefine if it's not already a 4-byte pointer var
    is_ptr = d is not None and d.getDataType().getLength() == 4 and "*" in tname
    if not is_ptr:
        try:
            arr = ArrayDataType(awe, 10, awe.getLength())
            end = b.add(10 * 0x44 - 1)
            clearListing(b, end)
            createData(b, arr)
            rep.append("g_aiWorkBuffer -> AiWorkEntry[10] (%d bytes)" % (10 * 0x44))
        except Exception as e:
            rep.append("ERR g_aiWorkBuffer array : %s" % str(e))
    else:
        rep.append("g_aiWorkBuffer looks like a pointer var; left as-is")
else:
    rep.append("g_aiWorkBuffer symbol not found")

print("\n".join(rep))
