
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.symbol import SourceType


ord_names = {    1: "accept",    2: "bind",    3: "closesocket",    4: "connect",    5: "getpeername",    6: "getsockname",    7: "getsockopt",    8: "htonl",    9: "htons",    10: "ioctlsocket",    11: "inet_addr",    12: "inet_ntoa",    13: "listen",    14: "ntohl",    15: "ntohs",    16: "recv",    17: "recvfrom",    18: "select",    19: "send",    20: "sendto",    21: "setsockopt",    22: "shutdown",    23: "socket",    24: "GetAddrInfoW",    25: "GetNameInfoW",    26: "WSApSetPostRoutine",    27: "FreeAddrInfoW",    28: "WPUCompleteOverlappedRequest",    29: "WSAAccept",    30: "WSAAddressToStringA",    31: "WSAAddressToStringW",    32: "WSACloseEvent",    33: "WSAConnect",    34: "WSACreateEvent",    35: "WSADuplicateSocketA",    36: "WSADuplicateSocketW",    37: "WSAEnumNameSpaceProvidersA",    38: "WSAEnumNameSpaceProvidersW",    39: "WSAEnumNetworkEvents",    40: "WSAEnumProtocolsA",    41: "WSAEnumProtocolsW",    42: "WSAEventSelect",    43: "WSAGetOverlappedResult",    44: "WSAGetQOSByName",    45: "WSAGetServiceClassInfoA",    46: "WSAGetServiceClassInfoW",    47: "WSAGetServiceClassNameByClassIdA",    48: "WSAGetServiceClassNameByClassIdW",    49: "WSAHtonl",    50: "WSAHtons",    51: "gethostbyaddr",    52: "gethostbyname",    53: "getprotobyname",    54: "getprotobynumber",    55: "getservbyname",    56: "getservbyport",    57: "gethostname",    58: "WSAInstallServiceClassA",    59: "WSAInstallServiceClassW",    60: "WSAIoctl",    61: "WSAJoinLeaf",    62: "WSALookupServiceBeginA",    63: "WSALookupServiceBeginW",    64: "WSALookupServiceEnd",    65: "WSALookupServiceNextA",    66: "WSALookupServiceNextW",    67: "WSANSPIoctl",    68: "WSANtohl",    69: "WSANtohs",    70: "WSAProviderConfigChange",    71: "WSARecv",    72: "WSARecvDisconnect",    73: "WSARecvFrom",    74: "WSARemoveServiceClass",    75: "WSAResetEvent",    76: "WSASend",    77: "WSASendDisconnect",    78: "WSASendTo",    79: "WSASetEvent",    80: "WSASetServiceA",    81: "WSASetServiceW",    82: "WSASocketA",    83: "WSASocketW",    84: "WSAStringToAddressA",    85: "WSAStringToAddressW",    86: "WSAWaitForMultipleEvents",    87: "WSCDeinstallProvider",    88: "WSCEnableNSProvider",    89: "WSCEnumProtocols",    90: "WSCGetProviderPath",    91: "WSCInstallNameSpace",    92: "WSCInstallProvider",    93: "WSCUnInstallNameSpace",    94: "WSCUpdateProvider",    95: "WSCWriteNameSpaceOrder",    96: "WSCWriteProviderOrder",    97: "freeaddrinfo",    98: "getaddrinfo",    99: "getnameinfo",    101: "WSAAsyncSelect",    102: "WSAAsyncGetHostByAddr",    103: "WSAAsyncGetHostByName",    104: "WSAAsyncGetProtoByNumber",    105: "WSAAsyncGetProtoByName",    106: "WSAAsyncGetServByPort",    107: "WSAAsyncGetServByName",    108: "WSACancelAsyncRequest",    109: "WSASetBlockingHook",    110: "WSAUnhookBlockingHook",    111: "WSAGetLastError",    112: "WSASetLastError",    113: "WSACancelBlockingCall",    114: "WSAIsBlocking",    115: "WSAStartup",    116: "WSACleanup",    151: "__WSAFDIsSet",    500: "WEP",}
#ord_names = {    1: b"accept",    2: b"bind",    3: b"closesocket",    4: b"connect",    5: b"getpeername",    6: b"getsockname",    7: b"getsockopt",    8: b"htonl",    9: b"htons",    10: b"ioctlsocket",    11: b"inet_addr",    12: b"inet_ntoa",    13: b"listen",    14: b"ntohl",    15: b"ntohs",    16: b"recv",    17: b"recvfrom",    18: b"select",    19: b"send",    20: b"sendto",    21: b"setsockopt",    22: b"shutdown",    23: b"socket",    24: b"GetAddrInfoW",    25: b"GetNameInfoW",    26: b"WSApSetPostRoutine",    27: b"FreeAddrInfoW",    28: b"WPUCompleteOverlappedRequest",    29: b"WSAAccept",    30: b"WSAAddressToStringA",    31: b"WSAAddressToStringW",    32: b"WSACloseEvent",    33: b"WSAConnect",    34: b"WSACreateEvent",    35: b"WSADuplicateSocketA",    36: b"WSADuplicateSocketW",    37: b"WSAEnumNameSpaceProvidersA",    38: b"WSAEnumNameSpaceProvidersW",    39: b"WSAEnumNetworkEvents",    40: b"WSAEnumProtocolsA",    41: b"WSAEnumProtocolsW",    42: b"WSAEventSelect",    43: b"WSAGetOverlappedResult",    44: b"WSAGetQOSByName",    45: b"WSAGetServiceClassInfoA",    46: b"WSAGetServiceClassInfoW",    47: b"WSAGetServiceClassNameByClassIdA",    48: b"WSAGetServiceClassNameByClassIdW",    49: b"WSAHtonl",    50: b"WSAHtons",    51: b"gethostbyaddr",    52: b"gethostbyname",    53: b"getprotobyname",    54: b"getprotobynumber",    55: b"getservbyname",    56: b"getservbyport",    57: b"gethostname",    58: b"WSAInstallServiceClassA",    59: b"WSAInstallServiceClassW",    60: b"WSAIoctl",    61: b"WSAJoinLeaf",    62: b"WSALookupServiceBeginA",    63: b"WSALookupServiceBeginW",    64: b"WSALookupServiceEnd",    65: b"WSALookupServiceNextA",    66: b"WSALookupServiceNextW",    67: b"WSANSPIoctl",    68: b"WSANtohl",    69: b"WSANtohs",    70: b"WSAProviderConfigChange",    71: b"WSARecv",    72: b"WSARecvDisconnect",    73: b"WSARecvFrom",    74: b"WSARemoveServiceClass",    75: b"WSAResetEvent",    76: b"WSASend",    77: b"WSASendDisconnect",    78: b"WSASendTo",    79: b"WSASetEvent",    80: b"WSASetServiceA",    81: b"WSASetServiceW",    82: b"WSASocketA",    83: b"WSASocketW",    84: b"WSAStringToAddressA",    85: b"WSAStringToAddressW",    86: b"WSAWaitForMultipleEvents",    87: b"WSCDeinstallProvider",    88: b"WSCEnableNSProvider",    89: b"WSCEnumProtocols",    90: b"WSCGetProviderPath",    91: b"WSCInstallNameSpace",    92: b"WSCInstallProvider",    93: b"WSCUnInstallNameSpace",    94: b"WSCUpdateProvider",    95: b"WSCWriteNameSpaceOrder",    96: b"WSCWriteProviderOrder",    97: b"freeaddrinfo",    98: b"getaddrinfo",    99: b"getnameinfo",    101: b"WSAAsyncSelect",    102: b"WSAAsyncGetHostByAddr",    103: b"WSAAsyncGetHostByName",    104: b"WSAAsyncGetProtoByNumber",    105: b"WSAAsyncGetProtoByName",    106: b"WSAAsyncGetServByPort",    107: b"WSAAsyncGetServByName",    108: b"WSACancelAsyncRequest",    109: b"WSASetBlockingHook",    110: b"WSAUnhookBlockingHook",    111: b"WSAGetLastError",    112: b"WSASetLastError",    113: b"WSACancelBlockingCall",    114: b"WSAIsBlocking",    115: b"WSAStartup",    116: b"WSACleanup",    151: b"__WSAFDIsSet",    500: b"WEP",}


st = getCurrentProgram().getSymbolTable()
fm = getCurrentProgram().getFunctionManager()
defSymbols = st.getDefinedSymbols()
ords = [k for k in st.getDefinedSymbols() if 'Ordinal_' in k.getName()]
for symbol in ords:
    try:
        on = ord_names.get(int(symbol.getName().split('_')[1]))
    except (IndexError, ValueError) as e:
        # print(f'{e} old: {symbol.getName()}')
        on = symbol.getName()
    # print(f'oldname {symbol.getName()} newname {on}')
    try:
    	symbol.setName(on, SourceType.USER_DEFINED)
    except Exception as e:
        print('Error: ',e)

for symbol in defSymbols:
    if symbol.getSymbolType() == SymbolType.CLASS and symbol.isGlobal():
        for child in st.getChildren(symbol):
            if child.getSymbolType() == SymbolType.FUNCTION:
                pass # print(f'symbol {symbol.getName()}:{child.getName()}') # symbol.getName() + " : " + child.getName())


ord_names = {
    1: b"accept",
    2: b"bind",
    3: b"closesocket",
    4: b"connect",
    5: b"getpeername",
    6: b"getsockname",
    7: b"getsockopt",
    8: b"htonl",
    9: b"htons",
    10: b"ioctlsocket",
    11: b"inet_addr",
    12: b"inet_ntoa",
    13: b"listen",
    14: b"ntohl",
    15: b"ntohs",
    16: b"recv",
    17: b"recvfrom",
    18: b"select",
    19: b"send",
    20: b"sendto",
    21: b"setsockopt",
    22: b"shutdown",
    23: b"socket",
    24: b"GetAddrInfoW",
    25: b"GetNameInfoW",
    26: b"WSApSetPostRoutine",
    27: b"FreeAddrInfoW",
    28: b"WPUCompleteOverlappedRequest",
    29: b"WSAAccept",
    30: b"WSAAddressToStringA",
    31: b"WSAAddressToStringW",
    32: b"WSACloseEvent",
    33: b"WSAConnect",
    34: b"WSACreateEvent",
    35: b"WSADuplicateSocketA",
    36: b"WSADuplicateSocketW",
    37: b"WSAEnumNameSpaceProvidersA",
    38: b"WSAEnumNameSpaceProvidersW",
    39: b"WSAEnumNetworkEvents",
    40: b"WSAEnumProtocolsA",
    41: b"WSAEnumProtocolsW",
    42: b"WSAEventSelect",
    43: b"WSAGetOverlappedResult",
    44: b"WSAGetQOSByName",
    45: b"WSAGetServiceClassInfoA",
    46: b"WSAGetServiceClassInfoW",
    47: b"WSAGetServiceClassNameByClassIdA",
    48: b"WSAGetServiceClassNameByClassIdW",
    49: b"WSAHtonl",
    50: b"WSAHtons",
    51: b"gethostbyaddr",
    52: b"gethostbyname",
    53: b"getprotobyname",
    54: b"getprotobynumber",
    55: b"getservbyname",
    56: b"getservbyport",
    57: b"gethostname",
    58: b"WSAInstallServiceClassA",
    59: b"WSAInstallServiceClassW",
    60: b"WSAIoctl",
    61: b"WSAJoinLeaf",
    62: b"WSALookupServiceBeginA",
    63: b"WSALookupServiceBeginW",
    64: b"WSALookupServiceEnd",
    65: b"WSALookupServiceNextA",
    66: b"WSALookupServiceNextW",
    67: b"WSANSPIoctl",
    68: b"WSANtohl",
    69: b"WSANtohs",
    70: b"WSAProviderConfigChange",
    71: b"WSARecv",
    72: b"WSARecvDisconnect",
    73: b"WSARecvFrom",
    74: b"WSARemoveServiceClass",
    75: b"WSAResetEvent",
    76: b"WSASend",
    77: b"WSASendDisconnect",
    78: b"WSASendTo",
    79: b"WSASetEvent",
    80: b"WSASetServiceA",
    81: b"WSASetServiceW",
    82: b"WSASocketA",
    83: b"WSASocketW",
    84: b"WSAStringToAddressA",
    85: b"WSAStringToAddressW",
    86: b"WSAWaitForMultipleEvents",
    87: b"WSCDeinstallProvider",
    88: b"WSCEnableNSProvider",
    89: b"WSCEnumProtocols",
    90: b"WSCGetProviderPath",
    91: b"WSCInstallNameSpace",
    92: b"WSCInstallProvider",
    93: b"WSCUnInstallNameSpace",
    94: b"WSCUpdateProvider",
    95: b"WSCWriteNameSpaceOrder",
    96: b"WSCWriteProviderOrder",
    97: b"freeaddrinfo",
    98: b"getaddrinfo",
    99: b"getnameinfo",
    101: b"WSAAsyncSelect",
    102: b"WSAAsyncGetHostByAddr",
    103: b"WSAAsyncGetHostByName",
    104: b"WSAAsyncGetProtoByNumber",
    105: b"WSAAsyncGetProtoByName",
    106: b"WSAAsyncGetServByPort",
    107: b"WSAAsyncGetServByName",
    108: b"WSACancelAsyncRequest",
    109: b"WSASetBlockingHook",
    110: b"WSAUnhookBlockingHook",
    111: b"WSAGetLastError",
    112: b"WSASetLastError",
    113: b"WSACancelBlockingCall",
    114: b"WSAIsBlocking",
    115: b"WSAStartup",
    116: b"WSACleanup",
    151: b"__WSAFDIsSet",
    500: b"WEP",
}




# ord_names[1] = "accept";
# ord_names[2] = "bind";
# ord_names[3] = "closesocket";
# ord_names[4] = "connect";
# ord_names[5] = "getpeername";
# ord_names[6] = "getsockname";
# ord_names[7] = "getsockopt";
# ord_names[8] = "htonl";
# ord_names[9] = "htons";
# ord_names[10] = "ioctlsocket";
# ord_names[11] = "inet_addr";
# ord_names[12] = "inet_ntoa";
# ord_names[13] = "listen";
# ord_names[14] = "ntohl";
# ord_names[15] = "ntohs";
# ord_names[16] = "recv";
# ord_names[17] = "recvfrom";
# ord_names[18] = "select";
# ord_names[19] = "send";
# ord_names[20] = "sendto";
# ord_names[21] = "setsockopt";
# ord_names[22] = "shutdown";
# ord_names[23] = "socket";
# ord_names[24] = "GetAddrInfoW";
# ord_names[25] = "GetNameInfoW";
# ord_names[26] = "WSApSetPostRoutine";
# ord_names[27] = "FreeAddrInfoW";
# ord_names[28] = "WPUCompleteOverlappedRequest";
# ord_names[29] = "WSAAccept";
# ord_names[30] = "WSAAddressToStringA";
# ord_names[31] = "WSAAddressToStringW";
# ord_names[32] = "WSACloseEvent";
# ord_names[33] = "WSAConnect";
# ord_names[34] = "WSACreateEvent";
# ord_names[35] = "WSADuplicateSocketA";
# ord_names[36] = "WSADuplicateSocketW";
# ord_names[37] = "WSAEnumNameSpaceProvidersA";
# ord_names[38] = "WSAEnumNameSpaceProvidersW";
# ord_names[39] = "WSAEnumNetworkEvents";
# ord_names[40] = "WSAEnumProtocolsA";
# ord_names[41] = "WSAEnumProtocolsW";
# ord_names[42] = "WSAEventSelect";
# ord_names[43] = "WSAGetOverlappedResult";
# ord_names[44] = "WSAGetQOSByName";
# ord_names[45] = "WSAGetServiceClassInfoA";
# ord_names[46] = "WSAGetServiceClassInfoW";
# ord_names[47] = "WSAGetServiceClassNameByClassIdA";
# ord_names[48] = "WSAGetServiceClassNameByClassIdW";
# ord_names[49] = "WSAHtonl";
# ord_names[50] = "WSAHtons";
# ord_names[51] = "gethostbyaddr";
# ord_names[52] = "gethostbyname";
# ord_names[53] = "getprotobyname";
# ord_names[54] = "getprotobynumber";
# ord_names[55] = "getservbyname";
# ord_names[56] = "getservbyport";
# ord_names[57] = "gethostname";
# ord_names[58] = "WSAInstallServiceClassA";
# ord_names[59] = "WSAInstallServiceClassW";
# ord_names[60] = "WSAIoctl";
# ord_names[61] = "WSAJoinLeaf";
# ord_names[62] = "WSALookupServiceBeginA";
# ord_names[63] = "WSALookupServiceBeginW";
# ord_names[64] = "WSALookupServiceEnd";
# ord_names[65] = "WSALookupServiceNextA";
# ord_names[66] = "WSALookupServiceNextW";
# ord_names[67] = "WSANSPIoctl";
# ord_names[68] = "WSANtohl";
# ord_names[69] = "WSANtohs";
# ord_names[70] = "WSAProviderConfigChange";
# ord_names[71] = "WSARecv";
# ord_names[72] = "WSARecvDisconnect";
# ord_names[73] = "WSARecvFrom";
# ord_names[74] = "WSARemoveServiceClass";
# ord_names[75] = "WSAResetEvent";
# ord_names[76] = "WSASend";
# ord_names[77] = "WSASendDisconnect";
# ord_names[78] = "WSASendTo";
# ord_names[79] = "WSASetEvent";
# ord_names[80] = "WSASetServiceA";
# ord_names[81] = "WSASetServiceW";
# ord_names[82] = "WSASocketA";
# ord_names[83] = "WSASocketW";
# ord_names[84] = "WSAStringToAddressA";
# ord_names[85] = "WSAStringToAddressW";
# ord_names[86] = "WSAWaitForMultipleEvents";
# ord_names[87] = "WSCDeinstallProvider";
# ord_names[88] = "WSCEnableNSProvider";
# ord_names[89] = "WSCEnumProtocols";
# ord_names[90] = "WSCGetProviderPath";
# ord_names[91] = "WSCInstallNameSpace";
# ord_names[92] = "WSCInstallProvider";
# ord_names[93] = "WSCUnInstallNameSpace";
# ord_names[94] = "WSCUpdateProvider";
# ord_names[95] = "WSCWriteNameSpaceOrder";
# ord_names[96] = "WSCWriteProviderOrder";
# ord_names[97] = "freeaddrinfo";
# ord_names[98] = "getaddrinfo";
# ord_names[99] = "getnameinfo";
# ord_names[101] = "WSAAsyncSelect";
# ord_names[102] = "WSAAsyncGetHostByAddr";
# ord_names[103] = "WSAAsyncGetHostByName";
# ord_names[104] = "WSAAsyncGetProtoByNumber";
# ord_names[105] = "WSAAsyncGetProtoByName";
# ord_names[106] = "WSAAsyncGetServByPort";
# ord_names[107] = "WSAAsyncGetServByName";
# ord_names[108] = "WSACancelAsyncRequest";
# ord_names[109] = "WSASetBlockingHook";
# ord_names[110] = "WSAUnhookBlockingHook";
# ord_names[111] = "WSAGetLastError";
# ord_names[112] = "WSASetLastError";
# ord_names[113] = "WSACancelBlockingCall";
# ord_names[114] = "WSAIsBlocking";
# ord_names[115] = "WSAStartup";
# ord_names[116] = "WSACleanup";
# ord_names[151] = "__WSAFDIsSet";
# ord_names[500] = "WEP";

