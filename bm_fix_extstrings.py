# Fix .bat/.com/.exe extension strings (clear split byte-data first)
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        clearListing,
        createAsciiString,
        createLabel,
        getDataAt,
        toAddr,
    )
except ImportError:
    pass
from ghidra.program.model.symbol import SourceType

US = SourceType.USER_DEFINED
rep = []
# clear whole contiguous region covering the 3 ext strings, then rebuild
clearListing(toAddr(0x0045B56C), toAddr(0x0045B57A))
for a, nm in [
    (0x0045B56C, "s_ext_bat"),
    (0x0045B571, "s_ext_com"),
    (0x0045B576, "s_ext_exe"),
]:
    try:
        ad = toAddr(a)
        createAsciiString(ad)
        createLabel(ad, nm, True, US)
        rep.append("STR %s @ %x = %r" % (nm, a, str(getDataAt(ad).getValue())))
    except Exception as e:
        rep.append("ERR %x : %s" % (a, str(e)))
print("\n".join(rep))
