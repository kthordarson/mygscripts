#@author kth
#@category mygscripts
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import EnumDataType

# -------- CONFIG --------
CACHE_SYMBOL = "DAT_00462628"
ENUM_NAME = "function_id"
PTR_SIZE = currentProgram.getDefaultPointerSize()

FUNCTION_MAP = {
    0: ("FID_FlsAlloc", "FlsAlloc"),
    1: ("FID_FlsFree", "FlsFree"),
    2: ("FID_FlsGetValue", "FlsGetValue"),
    3: ("FID_FlsSetValue", "FlsSetValue"),
    4: ("FID_InitializeCriticalSectionEx", "InitializeCriticalSectionEx"),
    5: ("FID_LCMapStringEx", "LCMapStringEx"),
    6: ("FID_LocaleNameToLCID", "LocaleNameToLCID"),
    7: ("FID_IsPackagedApp", "GetCurrentPackageFullName"),
}

symtab = currentProgram.getSymbolTable()
dtm = currentProgram.getDataTypeManager()

# -------- ENUM --------
enum_dt = dtm.getDataType("/" + ENUM_NAME)
if enum_dt is None:
    enum_dt = EnumDataType(ENUM_NAME, 4)
    dtm.addDataType(enum_dt, None)

for ordinal, (ename, _) in FUNCTION_MAP.items():
    if enum_dt.getName(ordinal) is None:
        enum_dt.add(ename, ordinal)

# -------- CACHE --------
# Start transaction for Ghidra
tid = currentProgram.startTransaction("Rename WinAPI Cache")
try:
    syms = symtab.getSymbols(CACHE_SYMBOL)
    if not syms:
        print("[!] Could not find symbol: " + CACHE_SYMBOL)

    for sym in syms:
        base = sym.getAddress()
        for ordinal, (_, api) in FUNCTION_MAP.items():
            addr = base.add(ordinal * PTR_SIZE)
            # Remove existing labels to avoid duplicates if re-run
            for existing in symtab.getSymbols(addr):
                if existing.getName().startswith("pfn_"):
                    existing.delete()

            symtab.createLabel(
                addr,
                "pfn_" + api,
                SourceType.USER_DEFINED
            )
    currentProgram.endTransaction(tid, True)
except Exception as e:
    print("[!] Error: " + str(e))
    currentProgram.endTransaction(tid, False)

print("[+] WinAPI resolver cache and function_id enum renamed")