# Bookmark/label authentication paths that call crypt_dispatch
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        currentProgram,
    )
except ImportError:
    pass
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import BookmarkType

fm = currentProgram.getFunctionManager()
bm = currentProgram.getBookmarkManager()
listing = currentProgram.getListing()
st = currentProgram.getSymbolTable()

# -------------------------------------------------
# Locate crypt_dispatch
# -------------------------------------------------
crypt_func = None  # fm.getFunction("crypt_dispatch")


for sym in st.getSymbols("crypt_dispatch"):
    if sym.getSymbolType() == SymbolType.FUNCTION:
        crypt_func = fm.getFunctionAt(sym.getAddress())
        break


if not crypt_func:
    print("[-] crypt_dispatch not found (rename it first)")
    exit()

print("[+] Found crypt_dispatch at", crypt_func.getEntryPoint())

# -------------------------------------------------
# Find callers
# -------------------------------------------------
callers = crypt_func.getCallingFunctions(None)

if not callers:
    print("[-] No callers found")
    exit()

print("[+] Found %d authentication candidates" % len(callers))

# -------------------------------------------------
# Helper: detect password comparison
# -------------------------------------------------
def contains_password_compare(func):
    for callee in func.getCalledFunctions(None):
        name = callee.getName()
        if name in ("strcmp", "strncmp", "memcmp"):
            return True
    return False

# -------------------------------------------------
# Process callers
# -------------------------------------------------
for func in callers:
    entry = func.getEntryPoint()

    # Bookmark function
    bm.setBookmark(
        entry,
        BookmarkType.INFO,
        "AUTH_PATH",
        "Calls crypt() for password verification"
    )

    # Rename generic functions
    if func.getName().startswith("FUN_"):
        new_name = "auth_check_" + entry.toString().replace("0x", "")
        func.setName(new_name, SourceType.USER)

    # Detect comparison
    has_compare = contains_password_compare(func)

    # Build comment
    comment = (
        "AUTHENTICATION FUNCTION\n"
        "-----------------------\n"
        "This function verifies a password using crypt().\n\n"
        "Flow:\n"
        "  user_input_password\n"
        "      ↓\n"
        "  crypt_dispatch(password, stored_hash)\n"
    )

    if has_compare:
        comment += "      ↓\n  strcmp / memcmp against stored hash\n"

    comment += "\nSECURITY NOTES:\n"
    comment += "  - Handles user-controlled password input\n"
    comment += "  - Uses legacy DES / MD5-crypt\n"
    comment += "  - Vulnerable to offline cracking\n"

    func.setComment(comment)

    print("[+] Labeled authentication path:", func.getName())

print("[✓] Authentication path labeling complete")
