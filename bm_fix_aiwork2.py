# Revert bad array; set g_aiWorkBuffer and g_currentRemotePlayer as AiWorkEntry*
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        clearListing,
        createData,
        createLabel,
        currentProgram,
        getDataAt,
        toAddr,
    )
except ImportError:
    pass
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.symbol import SourceType
from java.util import ArrayList

US = SourceType.USER_DEFINED
prog = currentProgram
dtm = prog.getDataTypeManager()
st = prog.getSymbolTable()
rep = []

al = ArrayList()
dtm.findDataTypes("AiWorkEntry", al)
awe = al.get(0)
AWEP = PointerDataType(awe)

# report labels in the clobbered range first
lo = toAddr(0x0045ED6C)
hi = toAddr(0x0045ED6C + 10 * 0x44 - 1)
rep.append("=== labels in %s..%s ===" % (lo, hi))
s = st.getSymbolIterator(lo, True)
while s.hasNext():
    sym = s.next()
    if sym.getAddress().compareTo(hi) > 0:
        break
    rep.append("  %s %s" % (sym.getAddress(), sym.getName()))

# 1) clear the bad array over the whole range
clearListing(lo, hi)

# 2) g_aiWorkBuffer @ 0x45ed6c -> AiWorkEntry*
a1 = toAddr(0x0045ED6C)
createData(a1, AWEP)
if (
    st.getPrimarySymbol(a1) is None
    or st.getPrimarySymbol(a1).getName() != "g_aiWorkBuffer"
):
    createLabel(a1, "g_aiWorkBuffer", True, US)
rep.append("g_aiWorkBuffer @ 45ed6c -> AiWorkEntry *")

# 3) g_currentRemotePlayer @ 0x45ed70 -> AiWorkEntry*
a2 = toAddr(0x0045ED70)
createData(a2, AWEP)
if (
    st.getPrimarySymbol(a2) is None
    or st.getPrimarySymbol(a2).getName() != "g_currentRemotePlayer"
):
    createLabel(a2, "g_currentRemotePlayer", True, US)
rep.append("g_currentRemotePlayer @ 45ed70 -> AiWorkEntry *")

# 4) show final state of the two + next few bytes
for off in [0x0045ED6C, 0x0045ED70, 0x0045ED74, 0x0045ED78]:
    d = getDataAt(toAddr(off))
    lbl = st.getPrimarySymbol(toAddr(off))
    rep.append(
        "  %08x %s %s"
        % (
            off,
            (d.getDataType().getName() if d else "<undef>"),
            (lbl.getName() if lbl else ""),
        )
    )
print("\n".join(rep))
