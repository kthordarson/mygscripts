#Fix .bat/.com/.exe extension strings (clear split byte-data first)
#@category BM
from ghidra.program.model.symbol import SourceType
US = SourceType.USER_DEFINED
rep = []
# clear whole contiguous region covering the 3 ext strings, then rebuild
clearListing(toAddr(0x0045b56c), toAddr(0x0045b57a))
for (a, nm) in [(0x0045b56c, "s_ext_bat"), (0x0045b571, "s_ext_com"), (0x0045b576, "s_ext_exe")]:
    try:
        ad = toAddr(a)
        createAsciiString(ad)
        createLabel(ad, nm, True, US)
        rep.append("STR %s @ %x = %r" % (nm, a, str(getDataAt(ad).getValue())))
    except Exception as e:
        rep.append("ERR %x : %s" % (a, str(e)))
print("\n".join(rep))
