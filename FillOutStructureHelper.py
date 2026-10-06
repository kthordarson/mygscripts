# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        askAddress,
        createSymbol,
        currentProgram,
        getBytes,
        getDataAt,
        getMemoryBlocks,
        getReferencesTo,
        getSymbolAt,
        isRunningHeadless,
        removeSymbol,
        toAddr,
        monitor,
    )
except ImportError:
    pass

from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler.util import FillOutStructureHelper
from ghidra.program.model.data import Structure, CategoryPath

dtm = currentProgram.getDataTypeManager()
cat = dtm.getCategory(CategoryPath("/Demangler"))
symtab = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()

ifc = DecompInterface()
ifc.openProgram(currentProgram)
helper = FillOutStructureHelper(currentProgram, monitor)


def walk(c):
    for dt in c.getDataTypes():
        if isinstance(dt, Structure) and dt.isZeroLength():  # empty placeholder
            yield dt
    for sub in c.getCategories():
        for dt in walk(sub):
            yield dt


for st in walk(cat):
    ns = symtab.getNamespace(st.getName(), None)  # class namespace
    if ns is None:
        print(f"Namespace for structure {st.getName()} not found.")
        continue
    for sym in symtab.getSymbols(ns):
        f = fm.getFunctionAt(sym.getAddress())
        if f is None or f.getParameterCount() == 0:
            print(
                f"Function at address {sym.getAddress()} not found or has no parameters. {st.getName()}"
            )
            continue
        res = ifc.decompileFunction(f, 60, monitor)
        hf = res.getHighFunction()
        if hf is None:
            print(
                f"Failed to decompile function at address {sym.getAddress()}. {st.getName()}"
            )
            continue
        this_var = hf.getLocalSymbolMap().getParamSymbol(0).getHighVariable()
        helper.processStructure(this_var, f, False, False, ifc)  # False = fill existing
    print("%s -> %d bytes" % (st.getPathName(), st.getLength()))
