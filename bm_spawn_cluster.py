#Rename + retype BM.EXE spawn/path/float cluster (Watcom conventions)
#@category BM
from ghidra.program.model.listing import ParameterImpl, ReturnParameterImpl, VariableStorage
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (CharDataType, IntegerDataType,
    VoidDataType, DoubleDataType, PointerDataType)
from java.util import ArrayList

prog = currentProgram
US = SourceType.USER_DEFINED
report = []

CHAR = CharDataType.dataType
INT  = IntegerDataType.dataType
VOID = VoidDataType.dataType
DBL  = DoubleDataType.dataType
def PTR(t): return PointerDataType(t)
CHARP  = PTR(CHAR)
CHARPP = PTR(PTR(CHAR))
CHARPPP= PTR(PTR(PTR(CHAR)))
VOIDP  = PTR(VOID)
INTP   = PTR(INT)

def R(n): return prog.getRegister(n)
def rstore(n): return VariableStorage(prog, R(n))
def sstore(off, sz=4): return VariableStorage(prog, off, sz)

def set_custom(addr, name, ret_dt, ret_store, params):
    f = getFunctionAt(toAddr(addr))
    if f is None:
        report.append("MISS custom %x" % addr); return
    try:
        f.setName(name, US)
        ret = ReturnParameterImpl(ret_dt, ret_store, prog)
        pl = ArrayList()
        for (pn, dt, st) in params:
            pl.add(ParameterImpl(pn, dt, st, prog))
        f.updateFunction("__cdecl", ret, pl, FunctionUpdateType.CUSTOM_STORAGE, True, US)
        report.append("OK  %s @ %x  (%d params)" % (name, addr, pl.size()))
    except Exception as e:
        report.append("ERR %s @ %x : %s" % (name, addr, str(e)))

def set_dynamic(addr, name, conv, ret_dt, params):
    f = getFunctionAt(toAddr(addr))
    if f is None:
        report.append("MISS dyn %x" % addr); return
    try:
        f.setName(name, US)
        ret = ReturnParameterImpl(ret_dt, prog)
        pl = ArrayList()
        for (pn, dt) in params:
            pl.add(ParameterImpl(pn, dt, prog))
        f.updateFunction(conv, ret, pl, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True, US)
        report.append("OK  %s @ %x  (%s, %d params)" % (name, addr, conv, pl.size()))
    except Exception as e:
        report.append("ERR %s @ %x : %s" % (name, addr, str(e)))

set_custom(0x00454efd, "crt_stpcpy", CHARP, rstore("EAX"),
    [("dst", CHARP, rstore("EAX")), ("src", CHARP, rstore("EDX"))])

set_custom(0x0045518c, "crt_splitpath_note_separator", INT, rstore("EAX"),
    [("ch", INT, rstore("EAX")), ("pLastSep", INTP, rstore("EDX"))])

set_custom(0x0045505f, "crt_splitpath_copy_field", CHARP, rstore("EAX"),
    [("ppOut", CHARPP, rstore("EAX")), ("dst", CHARP, rstore("EDX")),
     ("start", CHARP, rstore("EBX")), ("end", CHARP, rstore("ECX"))])

set_custom(0x0042ede0, "ui_show_yes_no_prompt", INT, rstore("EAX"),
    [("message", CHARP, rstore("EAX")), ("x", INT, rstore("EDX")),
     ("y", INT, rstore("EBX")), ("color", INT, rstore("ECX"))])

set_custom(0x0041779a, "set_installer_text_color", VOID, VariableStorage.VOID_STORAGE,
    [("color", INT, rstore("EAX"))])

set_custom(0x0045370e, "crt_spawnve", INT, rstore("EAX"),
    [("mode", INT, rstore("EAX")), ("path", CHARP, rstore("EDX")),
     ("argv", CHARPP, rstore("EBX")), ("envp", CHARPP, rstore("ECX"))])

set_custom(0x004551a0, "crt_makepath", VOID, VariableStorage.VOID_STORAGE,
    [("path", CHARP, rstore("EAX")), ("drive", CHARP, rstore("EDX")),
     ("dir", CHARP, rstore("EBX")), ("fname", CHARP, rstore("ECX")),
     ("ext", CHARP, sstore(4))])

set_custom(0x004550b1, "crt_splitpath", VOID, VariableStorage.VOID_STORAGE,
    [("path", CHARP, rstore("EAX")), ("out_drive", CHARP, rstore("EDX")),
     ("out_dir", CHARP, rstore("EBX")), ("out_fname", CHARP, rstore("ECX")),
     ("out_ext", CHARP, sstore(4)), ("out_extra", CHARP, sstore(8))])

set_custom(0x00454f0c, "crt_cenvarg", INT, rstore("EAX"),
    [("argv", CHARPP, rstore("EAX")), ("envp", CHARPP, rstore("EDX")),
     ("ppArgBlock", CHARPPP, rstore("EBX")), ("pArgLen", INTP, rstore("ECX")),
     ("ppEnvBlock", VOIDP, sstore(4)), ("pEnvLen", INTP, sstore(8)),
     ("mergeFlag", INT, sstore(12))])

set_dynamic(0x004563d6, "crt_scale_by_pow10", "__stdcall", DBL,
    [("value", DBL), ("exponent", INT)])

set_dynamic(0x0045538b, "crt_dospawn", "__cdecl", INT,
    [("mode", INT), ("progPath", CHARP), ("cmdLine", CHARP),
     ("environ", VOIDP), ("extra", INT)])

strs = [(0x0045b56c, "s_ext_bat"), (0x0045b571, "s_ext_com"), (0x0045b576, "s_ext_exe"),
        (0x0045b57b, "s_env_comspec"), (0x0045b583, "s_shell_cmd"), (0x0045b587, "s_shell_command")]
for (a, nm) in strs:
    try:
        ad = toAddr(a)
        d = getDataAt(ad)
        if d is None or not d.hasStringValue():
            clearListing(ad)
            createAsciiString(ad)
        createLabel(ad, nm, True, US)
        report.append("STR %s @ %x = %r" % (nm, a, str(getDataAt(ad).getValue())))
    except Exception as e:
        report.append("ERR str %x : %s" % (a, str(e)))

try:
    ga = toAddr(0x00460bf4)
    s = getSymbolAt(ga)
    if s is not None:
        s.setName("g_installerTextColor", US)
    else:
        createLabel(ga, "g_installerTextColor", True, US)
    report.append("GLB g_installerTextColor @ 460bf4")
except Exception as e:
    report.append("ERR global : %s" % str(e))

print("\n".join(report))
