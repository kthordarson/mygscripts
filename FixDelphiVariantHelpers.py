# Define Delphi/OLE VARIANT types and fix signatures of VARIANT helper functions
# original author: ReverseEngineer
# @author kth
# @category mygscripts
#@keybinding
#@menupath Tools.Delphi.Fix VARIANT Helpers
#@toolbar

try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from ghidra.program.model.data import *
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *
# from ghidra.app.util import DataTypeParser
from ghidra.util import Msg

program = currentProgram
dtm = program.getDataTypeManager()
listing = program.getListing()
symtab = program.getSymbolTable()

# ------------------------------------------------------------
# Helper: ensure data type exists
# ------------------------------------------------------------
def get_or_create(name, dt):
    existing = dtm.getDataType("/Delphi/" + name)
    if existing:
        return existing
    return dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER)

# ------------------------------------------------------------
# Define Delphi / OLE types
# ------------------------------------------------------------
HRESULT = get_or_create("HRESULT", TypedefDataType("HRESULT", IntegerDataType()))
VARIANT_BOOL = get_or_create("VARIANT_BOOL", TypedefDataType("VARIANT_BOOL", ShortDataType()))
LPCWSTR = get_or_create("LPCWSTR", PointerDataType(WideCharDataType()))
UINT = get_or_create("UINT", UnsignedIntegerDataType())

# ------------------------------------------------------------
# Function signature for VarBoolFromOleStr
# ------------------------------------------------------------
def apply_varbool_signature(func):
    params = []
    params.append(ParameterImpl("pszOleStr", LPCWSTR, program))
    params.append(ParameterImpl("vtType", UINT, program))
    params.append(ParameterImpl("pOutBool", PointerDataType(VARIANT_BOOL), program))

    func.setReturnType(HRESULT, SourceType.USER_DEFINED)
    func.replaceParameters(
        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        True,
        SourceType.USER_DEFINED,
        params
    )
if __name__ == "__main__":
    # ------------------------------------------------------------
    # Main heuristic scan
    # ------------------------------------------------------------
    for func in listing.getFunctions(True):
        name = func.getName()
        # print("Checking function: " + name)
        refs = False
        for instr in listing.getInstructions(func.getBody(), True):
            for ref in instr.getReferencesFrom():
                sym = symtab.getSymbol(ref)
                if sym and sym.getName() in ("LStrFromWStr", "TryStrToBool"):
                    refs = True
                    print("  Found reference to " + sym.getName())
                    break
            if refs:
                break

        if not refs:
            continue

        # Check for VT_BSTR constant
        body = func.getBody()
        vt_bstr_found = False
        for instr in listing.getInstructions(body, True):
            if instr.toString().find("0x400") != -1:
                vt_bstr_found = True
                print("  Found VT_BSTR constant in instruction: " + instr.toString())
                break

        if not vt_bstr_found:
            continue

        # Rename and apply signature
        Msg.info(None, "Fixing Delphi VARIANT helper: " + func.getName())
        func.setName("VarBoolFromOleStr", SourceType.USER_DEFINED)
        apply_varbool_signature(func)

        # Comment
        func.setComment(
            "Delphi VARIANT helper\n"
            "Converts VT_BSTR (OLE string) to VARIANT_BOOL\n"
            "Uses LStrFromWStr + TryStrToBool\n"
            "Returns HRESULT",
            CodeUnit.PLATE_COMMENT
        )

    Msg.info(None, "Delphi VARIANT helper auto-fix complete.")