# Iterate over import symbols and apply signatures

import ghidra.app.script
from ghidra.program.model.symbol import Symbol

signature_map = {
    "_acmdln": {"return_type": "LPSTR", "parameters": []},
    "atoi": {"return_type": "int", "parameters": [("const char*", "str")]},
    "malloc": {"return_type": "void*", "parameters": [("size_t", "size")]},
    "free": {"return_type": "void", "parameters": [("void*", "ptr")]},
    "fopen": {"return_type": "FILE*", "parameters": [("const char*", "filename"), ("const char*", "mode")]},
    "fclose": {"return_type": "int", "parameters": [("FILE*", "stream")]},
    "printf": {"return_type": "int", "parameters": [("const char*", "format"), ("...*", "args")]},
    "snprintf": {"return_type": "int", "parameters": [("char*", "buffer"), ("size_t", "size"), ("const char*", "format"), ("...*", "args")]},
    "_vsnprintf": {"return_type": "int", "parameters": [("char*", "buffer"), ("size_t", "size"), ("const char*", "format"), ("va_list", "args")]},
    "memcpy": {"return_type": "void*", "parameters": [("void*", "dest"), ("const void*", "src"), ("size_t", "n")]},
    "memset": {"return_type": "void*", "parameters": [("void*", "s"), ("int", "c"), ("size_t", "n")]},
    "strlen": {"return_type": "size_t", "parameters": [("const char*", "str")]},
    "strcpy": {"return_type": "char*", "parameters": [("char*", "dest"), ("const char*", "src")]},
    "strncpy": {"return_type": "char*", "parameters": [("char*", "dest"), ("const char*", "src"), ("size_t", "n")]},
    "strcat": {"return_type": "char*", "parameters": [("char*", "dest"), ("const char*", "src")]},
    "strchr": {"return_type": "char*", "parameters": [("const char*", "str"), ("int", "ch")]},
    "strrchr": {"return_type": "char*", "parameters": [("const char*", "str"), ("int", "ch")]},
    "strcmp": {"return_type": "int", "parameters": [("const char*", "str1"), ("const char*", "str2")]},
    "strtok": {"return_type": "char*", "parameters": [("char*", "str"), ("const char*", "delim")]},
    "exit": {"return_type": "void", "parameters": [("int", "status")]},
    "abort": {"return_type": "void", "parameters": []},
    "memcmp": {"return_type": "int", "parameters": [("const void*", "ptr1"), ("const void*", "ptr2"), ("size_t", "num")]},
    "realloc": {"return_type": "void*", "parameters": [("void*", "ptr"), ("size_t", "size")]},
    "calloc": {"return_type": "void*", "parameters": [("size_t", "count"), ("size_t", "size")]},
    "localtime": {"return_type": "struct tm*", "parameters": [("const time_t*", "time")]},
    "time": {"return_type": "time_t", "parameters": [("time_t*", "t")]},
    "gmtime": {"return_type": "struct tm*", "parameters": [("const time_t*", "time")]},
    "getenv": {"return_type": "char*", "parameters": [("const char*", "name")]},
    "setenv": {"return_type": "int", "parameters": [("const char*", "name"), ("const char*", "value"), ("int", "overwrite")]},
    "putenv": {"return_type": "int", "parameters": [("const char*", "str")]},
    "signal": {"return_type": "sighandler_t", "parameters": [("int", "sig"), ("sighandler_t", "handler")]},
    "puts": {"return_type": "int", "parameters": [("const char*", "str")]},
    "getchar": {"return_type": "int", "parameters": []},
    "CreateFileA": {"return_type": "HANDLE", "parameters": [("LPCTSTR", "lpFileName"), ("DWORD", "dwDesiredAccess"), ("DWORD", "dwShareMode"), ("LPSECURITY_ATTRIBUTES", "lpSecurityAttributes"), ("DWORD", "dwCreationDisposition"), ("DWORD", "dwFlagsAndAttributes"), ("HANDLE", "hTemplateFile")]},
    "ReadFile": {"return_type": "BOOL", "parameters": [("HANDLE", "hFile"), ("LPVOID", "lpBuffer"), ("DWORD", "nNumberOfBytesToRead"), ("LPDWORD", "lpNumberOfBytesRead"), ("LPOVERLAPPED", "lpOverlapped")]},
    "WriteFile": {"return_type": "BOOL", "parameters": [("HANDLE", "hFile"), ("LPCVOID", "lpBuffer"), ("DWORD", "nNumberOfBytesToWrite"), ("LPDWORD", "lpNumberOfBytesWritten"), ("LPOVERLAPPED", "lpOverlapped")]},
    "GetLastError": {"return_type": "DWORD", "parameters": []},
    "Sleep": {"return_type": "VOID", "parameters": [("DWORD", "dwMilliseconds")]},
    "GetProcAddress": {"return_type": "FARPROC", "parameters": [("HMODULE", "hModule"), ("LPCSTR", "lpProcName")]},
}


def apply_signature_to_import(symbol, signature_map):
    function_name = symbol.getName()
    print(f"Processing {function_name}")
    if function_name in signature_map:
        signature = signature_map[function_name]
        return_type = signature["return_type"]
        parameters = signature["parameters"]

        # Here you can apply the signature in Ghidra
        # For example: renaming function, applying argument types, etc.
        # Ghidra example: function.setReturnType(return_type) and so on.


def apply_signatures_and_rename_variables():
    # symbol_table = currentProgram.getSymbolTable()
    # symbol_table = currentProgram().getSymbolTable()
    symbol_table = [k for k in currentProgram().getSymbolTable().getExternalSymbols()]
    print(f"Found {len(symbol_table)} symbols in the symbol table")
    for symbol in symbol_table:  # .getSymbols():
        if symbol.getName() in signature_map:
            apply_signature_to_import(symbol, signature_map)
        else:
            print(f"Skipping {symbol.getName()} as it's not in the signature map")


# Main call
apply_signatures_and_rename_variables()
