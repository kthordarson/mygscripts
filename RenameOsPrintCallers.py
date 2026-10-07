# Find functions named FUN_* that call os_print_write, and rename them
# using the tag string passed as the 5th argument (module/function name).
# @author kth
# @category mygscripts

try:
    from ghidra.ghidra_builtins import (
        currentProgram,
        getByte,
        getFunctionContaining,
        println,
        toAddr,
    )
except ImportError:
    pass
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompileOptions
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.util.task import ConsoleTaskMonitor

from ghidra.app.util import NamespaceUtils
from ghidra.program.model.data import (
    Array,
    CategoryPath,
    PointerDataType,
    StructureDataType,
    DataTypeConflictHandler,
)
from ghidra.program.model.listing import VariableUtilities, GhidraClass
from java.lang import ArrayIndexOutOfBoundsException
import re

MAX_DEPTH = 12
MAX_STR_LEN = 128
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def eval_varnode(v, d):
    if v is None or d > MAX_DEPTH:
        return None
    if v.isConstant() or v.isAddress():
        return v.getOffset()
    o = v.getDef()
    if o is None:
        return None
    try:
        opcode = o.getOpcode()
        if opcode in (PcodeOp.COPY, PcodeOp.CAST):
            return eval_varnode(o.getInput(0), d + 1)
        if opcode in (PcodeOp.PTRSUB, PcodeOp.INT_ADD):
            a = eval_varnode(o.getInput(0), d + 1)
            b = eval_varnode(o.getInput(1), d + 1)
            if a is not None and b is not None:
                return a + b
            return None
        if opcode == PcodeOp.PTRADD:
            a = eval_varnode(o.getInput(0), d + 1)
            b = eval_varnode(o.getInput(1), d + 1)
            c = eval_varnode(o.getInput(2), d + 1)
            if a is not None and b is not None and c is not None:
                return a + b * c
            return None
    except Exception:
        pass
    return None


def read_cstring(str_addr):
    if str_addr is None:
        return None
    try:
        a = toAddr(str_addr)
        s = []
        for i in range(MAX_STR_LEN):
            c = getByte(a.add(i)) & 255
            if c == 0:
                break
            if c < 32 or c > 126:
                return None
            s.append(chr(c))
        return "".join(s) if len(s) > 0 else None
    except Exception:
        return None


def run():
    # t = toAddr(0x404800)
    # 004054e0 in cwmp
    # 00405f10 __assert_fail in cwmp
    # 0014f570 __assert_fail in libcmm.so
    # 00405150 __assert_fail in httpd
    # 004037c0 __assert_fail in pjusa
    # 00402f60 __assert_fail in tmpd
    # 004c4278 __assert_fail in tmpd
    # 00402b00 __assert_fail in tdpd
    # 0x402300 os_print_write in tr143d
    # 0014ddb0 os_print_write in libcmm.so
    # 00404800 os_print_write in httpd
    # 0010d630 os_print_write in libtp1905
    # 00102e80 os_print_write in libplatform
    # 00402d00 os_print_write in tmpd
    # 004028f0 os_print_write in tdpd
    # 00101d80 os_print_write in liblte.so
    # 002cb324 util_execSystem in libcmm.so
    # 001501b0 util_execSystem in libcmm.so
    # 00366138 mtwf_dbg_prt in mt_wifi.ko
    # 001571c0 printk in mtk_wrap.ko
    # 00822000 printk in mt_wifi.ko
    # 004022c0 printk in handle_card
    # 004099b0 log_message in tp1905cli
    # 00403ab4 log_message in nrd
    func_address = toAddr(0x00101D80)

    monitor = ConsoleTaskMonitor()
    di = DecompInterface()
    di.openProgram(currentProgram)
    n = 0
    u = 0
    q = None

    ref_functions = [
        "os_print_write",
        "__assert_fail",
    ]
    prefix = "FUN_"
    sm = currentProgram.getSymbolTable()
    symb = sm.getExternalSymbols()
    symbols = [
        {"name": k.getName(), "address": k.references[0].fromAddress}
        for k in sm.getExternalSymbols()
        if k.getName() in ref_functions
    ]
    funcList = [
        f
        for f in currentProgram.getListing().getFunctions(True)
        if prefix in f.getName()
    ]
    nodes = [
        {
            "func": k,
            "callers": list(k.getCallingFunctions(monitor)),
            "calls": list(k.getCalledFunctions(monitor)),
        }
        for k in funcList
    ]
    # refs = [list(currentProgram.getReferenceManager().getReferencesTo(k['address'])) for k in symbols]
    funcs_test = []
    seen = set()
    for node in nodes:
        for c in node["calls"]:
            call_func_name = c.getName()
            this_function = node["func"].getName()
            if call_func_name in ref_functions:
                # print(f'{this_function} calls {call_func_name} @ {c.getEntryPoint()}')
                seen.add(call_func_name)
                funcitem = {
                    "func": node["func"],
                    "c": c,
                }
                funcs_test.append(funcitem)
    # _ = [print(f'name: {k['func'].getName()} xrefs: {len(k['callers'])}') for k in nodes if len(k['callers'])>3]
    # _ = [print(f'name: {k['func'].getName()} xrefs: {len(k['calls'])}') for k in nodes if len(k['calls'])>3]

    funcs = []
    seen = set()
    r = currentProgram.getReferenceManager().getReferencesTo(func_address)
    while r.hasNext():
        f = getFunctionContaining(r.next().getFromAddress())
        if f is not None and f.getName().startswith("FUN_") and f not in seen:
            seen.add(f)
            funcs.append(f)
        else:
            println("SKIP " + str(f) + " @ " + str(f))
    println("Found " + str(len(funcs)) + " functions calling " + str(func_address))

    for f in funcs:
        new_name = None
        h = di.decompileFunction(f, 30, monitor).getHighFunction()
        # ops = [k for k in h.getPcodeOps() if k.getOpcode()==PcodeOp.CALL and k.getNumInputs() >= 4]
        # _ = [print(read_cstring(eval_varnode(o.getInput(4), 0))) for o in ops]
        if h is not None:
            it = h.getPcodeOps()
            while it.hasNext():
                o = it.next()
                if o.getOpcode() == PcodeOp.CALL and o.getNumInputs() >= 4:
                    q = read_cstring(eval_varnode(o.getInput(5), 0))
                    # os_print_write(0,1,"tr143","src/tr143_load.c","CAF_download_trafficDetection",0x6d2,"RxThroughput[%d] > [%d]",local_2e4 * 1000,*(int *)(param_1 + 0x44c) << 3);
                    # __assert_fail("(pRecvBuf != NULL) && (pUserData != NULL) && (pType != NULL)","./src/cwmp_rpc.c",0x65f,"cwmp_handleFault");
                    # mtwf_dbg_prt(param_1,6,1,"HQA_SetFrequencyOffsetToBufferBin",0xead,"Not support\n",param_7,param_8);
                    if q is not None and IDENT_RE.match(q):
                        new_name = q
                        break
                    else:
                        println(
                            "NOMATCH "
                            + f.getName()
                            + " @ "
                            + str(f.getEntryPoint())
                            + " q: "
                            + str(q)
                        )
        if new_name is None:
            println(
                "UNRESOLVED "
                + f.getName()
                + " @ "
                + str(f.getEntryPoint())
                + " q: "
                + str(q)
            )
            u += 1
            continue
        si = currentProgram.getSymbolTable().getSymbols(new_name)
        if si.hasNext():
            new_name = new_name + "_" + str(f.getEntryPoint())
        old = f.getName()
        f.setName(new_name, SourceType.USER_DEFINED)
        println(old + " -> " + new_name + " @ " + str(f.getEntryPoint()))
        n += 1

    println(
        "SUMMARY candidates="
        + str(len(funcs))
        + " renamed="
        + str(n)
        + " unresolved="
        + str(u)
    )


if __name__ == "__main__":
    run()
