# Rename and retype LibTomCrypt wrapper functions
# @author kth
# @category mygscripts
# @keybinding
# @menupath
# @toolbar

try:
    from ghidra.ghidra_builtins import currentProgram
except ImportError:
    pass
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    PointerDataType, UnsignedLongDataType, UnsignedIntegerDataType,
    UnsignedCharDataType, CharDataType, VoidDataType, IntegerDataType,
    StructureDataType
)
from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl
from java.util import ArrayList

fm = currentProgram.getFunctionManager()
dtm = currentProgram.getDataTypeManager()
af = currentProgram.getAddressFactory()
space = af.getDefaultAddressSpace()

# ----------------------------------------------------------------------
# Helper: create pointer type
# ----------------------------------------------------------------------
def ptr(dt):
    return PointerDataType(dt)

# ----------------------------------------------------------------------
# Common data types
# ----------------------------------------------------------------------
uint8_t = UnsignedCharDataType()    # used as byte
ulong = UnsignedLongDataType()
uint32 = UnsignedIntegerDataType()
int_t = IntegerDataType()
char_t = CharDataType()

mp_int = dtm.getDataType("/ltc/mp_int")
if mp_int is None:
    mp_int = dtm.addDataType(StructureDataType("mp_int", 0), None)

# ----------------------------------------------------------------------
# Function definitions: address -> definition
# ----------------------------------------------------------------------
FUNCTIONS = {
    0x140016590: {
        "name": "base64_encode_ex",
        "ret": int_t,
        "params": [
            ("in", ptr(uint8_t)),
            ("inlen", ulong),
            ("out", ptr(uint8_t)),
            ("outlen", ptr(ulong)),
            ("alphabet", ptr(char_t)),
            ("flags", ulong),
        ],
    },

    0x140017360: {
        "name": "ltc_mp_free_checked",
        "ret": int_t,
        "params": [("a", ptr(ptr(mp_int)))],
    },

    0x140017530: {
        "name": "ltc_mp_init_copy_checked",
        "ret": int_t,
        "params": [
            ("src", ptr(ptr(mp_int))),
            ("dst", ptr(mp_int)),
        ],
    },

    0x1400175D0: {
        "name": "ltc_mp_init_checked",
        "ret": int_t,
        "params": [("a", ptr(ptr(mp_int)))],
    },

    0x1400176E0: {
        "name": "ltc_mp_get_u32",
        "ret": uint32,
        "params": [("a", ptr(mp_int))],
    },

    0x140017A40: {
        "name": "ltc_mp_clear_checked",
        "ret": int_t,
        "params": [("a", ptr(ptr(mp_int)))],
    },

    0x140017BA0: {
        "name": "ltc_mp_add_checked",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("b", ptr(mp_int)),
            ("c", ptr(mp_int)),
        ],
    },

    0x140017CD0: {
        "name": "ltc_mp_sub_checked",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("b", ptr(mp_int)),
            ("c", ptr(mp_int)),
        ],
    },

    0x140017E00: {
        "name": "ltc_mp_mul_checked",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("b", ptr(mp_int)),
            ("c", ptr(mp_int)),
        ],
    },

    0x140018170: {
        "name": "ltc_mp_get_unsigned",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("index", ulong),
            ("out", ptr(ulong)),
        ],
    },

    0x140018210: {
        "name": "ltc_mp_div_checked",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("b", ptr(mp_int)),
            ("c", ptr(mp_int)),
        ],
    },

    0x1400182C0: {
        "name": "ltc_mp_mod_checked",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("b", ptr(mp_int)),
            ("c", ptr(mp_int)),
        ],
    },

    0x140018370: {
        "name": "ltc_mp_exptmod_checked",
        "ret": int_t,
        "params": [
            ("G", ptr(mp_int)),
            ("X", ptr(mp_int)),
            ("P", ptr(mp_int)),
            ("Y", ptr(mp_int)),
        ],
    },

    0x140018450: {
        "name": "ltc_mp_gcd_checked",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("b", ptr(mp_int)),
            ("c", ptr(mp_int)),
        ],
    },

    0x140018530: {
        "name": "ltc_mp_lcm_checked",
        "ret": int_t,
        "params": [
            ("a", ptr(mp_int)),
            ("b", ptr(mp_int)),
            ("c", ptr(mp_int)),
        ],
    },
}

# ----------------------------------------------------------------------
# Apply renames and prototypes
# ----------------------------------------------------------------------
for addr, info in FUNCTIONS.items():
    gh_addr = space.getAddress(addr)
    func = fm.getFunctionAt(gh_addr)
    if not func:
        print("[!] No function at", hex(addr))
        continue

    # Set function name
    func.setName(info["name"], SourceType.USER_DEFINED)

    # Create return parameter
    ret_param = ReturnParameterImpl(info["ret"], currentProgram)

    # Create parameter list
    params = ArrayList()
    for pname, ptype in info["params"]:
        params.add(ParameterImpl(pname, ptype, currentProgram))

    # Update function signature (callingConvention, return, params, updateType, force, sourceType)
    func.updateFunction(None, ret_param, params, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True, SourceType.USER_DEFINED)

    print("[+] Updated:", info["name"])

print("[*] LibTomCrypt wrappers renamed and retyped successfully")
