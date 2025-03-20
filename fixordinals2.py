from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import Function
from ghidra.app.util import NamespaceUtils

def resolve_ordinal_symbols():
    # Get the current program
    program = getCurrentProgram()
    symbol_table = program.getSymbolTable()
    function_mgr = program.getFunctionManager()
    memory = program.getMemory()

    # Dictionary to store known ordinal mappings
    # Format: (dll_name.lower(), ordinal): (function_name, param_count, return_type)
    ordinal_mappings = {
        ("kernel32.dll", 1): ("HeapAlloc", 3, "pointer"),
        ("user32.dll", 16): ("MessageBoxA", 4, "int"),

        # wsock32.dll (Winsock 1.1) mappings
        ("wsock32.dll", 1): ("accept", 3, "socket"),           # SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen)
        ("wsock32.dll", 2): ("bind", 3, "int"),               # int bind(SOCKET s, const struct sockaddr *addr, int namelen)
        ("wsock32.dll", 3): ("closesocket", 1, "int"),        # int closesocket(SOCKET s)
        ("wsock32.dll", 4): ("connect", 3, "int"),            # int connect(SOCKET s, const struct sockaddr *name, int namelen)
        ("wsock32.dll", 6): ("gethostbyname", 1, "pointer"),  # struct hostent *gethostbyname(const char *name)
        ("wsock32.dll", 11): ("gethostname", 2, "int"),       # int gethostname(char *name, int namelen)
        ("wsock32.dll", 13): ("getsockname", 3, "int"),       # int getsockname(SOCKET s, struct sockaddr *name, int *namelen)
        ("wsock32.dll", 16): ("htonl", 1, "uint"),            # u_long htonl(u_long hostlong)
        ("wsock32.dll", 17): ("htons", 1, "uint"),            # u_short htons(u_short hostshort)
        ("wsock32.dll", 22): ("listen", 2, "int"),            # int listen(SOCKET s, int backlog)
        ("wsock32.dll", 23): ("ntohl", 1, "uint"),            # u_long ntohl(u_long netlong)
        ("wsock32.dll", 24): ("ntohs", 1, "uint"),            # u_short ntohs(u_short netshort)
        ("wsock32.dll", 26): ("recv", 4, "int"),              # int recv(SOCKET s, char *buf, int len, int flags)
        ("wsock32.dll", 27): ("recvfrom", 6, "int"),          # int recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
        ("wsock32.dll", 30): ("send", 4, "int"),              # int send(SOCKET s, const char *buf, int len, int flags)
        ("wsock32.dll", 31): ("sendto", 6, "int"),            # int sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen)
        ("wsock32.dll", 33): ("setsockopt", 5, "int"),        # int setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen)
        ("wsock32.dll", 34): ("shutdown", 2, "int"),          # int shutdown(SOCKET s, int how)
        ("wsock32.dll", 35): ("socket", 3, "socket"),         # SOCKET socket(int af, int type, int protocol)
        ("wsock32.dll", 52): ("WSAStartup", 2, "int"),        # int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
        ("wsock32.dll", 55): ("WSACleanup", 0, "int"),        # int WSACleanup(void)
        ("wsock32.dll", 57): ("WSAGetLastError", 0, "int"),   # int WSAGetLastError(void)
    }

    # Get all external references
    symbols = symbol_table.getExternalSymbols()

    for symbol in symbols:
        name = symbol.getName()

        # Look for ordinal-only symbols
        if name.startswith("Ordinal_"):
            try:
                # Ensure the symbol is an external symbol with a valid external location
                if symbol.getSymbolType() != SymbolType.EXTERNAL:
                    print("Skipping {}: Not an external symbol".format(name))
                    continue

                ext_loc = symbol.getParentNamespace()
                if ext_loc is None or ext_loc.getName() == "Global":
                    print("Skipping {}: No valid external location".format(name))
                    continue

                ordinal_num = int(name.split("_")[1])
                dll_name = ext_loc.getName().lower()  # Use namespace name as DLL name

                # Check if we have a mapping for this ordinal
                key = (dll_name, ordinal_num)
                if key in ordinal_mappings:
                    func_name, param_count, ret_type = ordinal_mappings[key]

                    # Get or create the function at this address
                    address = symbol.getAddress()
                    func = function_mgr.getFunctionAt(address)

                    if func is None:
                        func = function_mgr.createFunction(func_name, address, None, SourceType.IMPORTED)

                    # Set function name
                    symbol.setName(func_name, SourceType.IMPORTED)

                    # Set calling convention to __stdcall (standard for Windows DLLs)
                    func.setCallingConvention("__stdcall")

                    # Clear existing parameters and set new ones
                    func.removeAllParameters()

                    # Add generic parameters based on count
                    for i in range(param_count):
                        func.addParameter(None, "param_" + str(i + 1), "int", 4)

                    # Set return type based on our mapping
                    if ret_type == "pointer":
                        func.setReturnType(program.getDataTypeManager().getPointer(None), SourceType.IMPORTED)
                    elif ret_type == "int":
                        func.setReturnType(program.getDataTypeManager().getDataType("/int"), SourceType.IMPORTED)
                    elif ret_type == "uint":
                        func.setReturnType(program.getDataTypeManager().getDataType("/uint"), SourceType.IMPORTED)
                    elif ret_type == "socket":
                        func.setReturnType(program.getDataTypeManager().getDataType("/uint"), SourceType.IMPORTED)

                    print("Renamed {} from {} to {} at {}".format(dll_name, name, func_name, address))

                else:
                    print("No mapping found for {} ordinal {}".format(dll_name, ordinal_num))

            except Exception as e:
                print("Error processing {}: {}".format(name, str(e)))

if __name__ == "__main__":
    resolve_ordinal_symbols()