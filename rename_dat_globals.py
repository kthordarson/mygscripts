# @description Rename DAT_* globals using access pattern heuristics
# @category mygscripts
# @author kth

try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.data import (
    ByteDataType,
    WordDataType,
    DWordDataType,
    QWordDataType,
    PointerDataType,
    ArrayDataType,
)
from ghidra.program.model.listing import CodeUnit
from ghidra.util import Msg

program = currentProgram
symbolTable = program.getSymbolTable()
listing = program.getListing()
refManager = program.getReferenceManager()
dataTypeManager = program.getDataTypeManager()


def infer_type_and_name(symbol):
    addr = symbol.getAddress()
    refs = refManager.getReferencesTo(addr)

    sizes = set()
    is_pointer = False
    is_array = False
    is_counter = False

    for ref in refs:
        instr = listing.getInstructionAt(ref.getFromAddress())
        if not instr:
            continue

        flow = instr.getFlowType()
        mnemonic = instr.getMnemonicString().lower()

        # Heuristic: pointer usage
        if mnemonic in ("mov", "lea", "push"):
            for op in instr.getOpObjects(0):
                if op == addr:
                    is_pointer = True

        # Heuristic: counter
        if mnemonic in ("inc", "dec", "add", "sub"):
            is_counter = True

        # Operand size
        try:
            sizes.add(instr.getDefaultOperandRepresentation(0))
        except Exception as e:
            print("[!] infer_type_and_name: {}".format(e))

        # Indexed access → array/buffer
        if "[" in instr.toString():
            is_array = True

    # Infer data type
    if is_pointer:
        dtype = PointerDataType(dataTypeManager.getDataType("/byte"))
        type_name = "ptr"
    elif is_array:
        dtype = ArrayDataType(ByteDataType(), 0x100, 1)
        type_name = "buffer"
    else:
        # Default scalar
        dtype = DWordDataType()
        type_name = "value"

    # Improve naming
    if is_counter:
        type_name = "count"

    new_name = "g_%s_%s" % (type_name, addr.toString().replace("0x", ""))

    return new_name, dtype


def apply_changes(symbol, new_name, dtype):
    addr = symbol.getAddress()

    # Rename
    try:
        symbol.setName(new_name, SourceType.USER_DEFINED)
    except Exception as e:
        print("[!] apply_changes: {}".format(e))
        Msg.warn(None, "Rename failed for %s" % symbol.getName())

    # Apply data type
    try:
        listing.clearCodeUnits(addr, addr.add(dtype.getLength() - 1), False)
        listing.createData(addr, dtype)
    except Exception as ex:
        print("[!] apply_changes: {}".format(ex))
        Msg.warn(None, "Type apply failed for %s" % new_name)


def main():
    symbols = symbolTable.getAllSymbols(True)
    count = 0

    for sym in symbols:
        if sym.getSymbolType() != SymbolType.LABEL:
            continue

        name = sym.getName()
        if not name.startswith("DAT_"):
            continue

        new_name, dtype = infer_type_and_name(sym)
        apply_changes(sym, new_name, dtype)
        count += 1

    Msg.info(None, "Renamed %d DAT_ symbols" % count)


main()
