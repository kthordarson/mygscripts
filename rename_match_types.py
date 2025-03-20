import re

def find_calling_functions(function_code, target_function="SendMessageA"):
    """
    Finds all functions in a program's disassembly that call the target function.
    
    Args:
    function_code (str): A string containing the disassembly or source code.
    target_function (str): The name of the function to search for (default is 'SendMessageA').
    
    Returns:
    List of function names that call the target function.
    """
    # Regular expression to find all function calls to the target function
    pattern = r"\b(\w+)\s*\([^\)]*" + re.escape(target_function) + r"\([^\)]*\)"
    
    # Find all matches
    matches = re.findall(pattern, function_code)
    
    # Return the matches (function names)
    return matches


def rename_variables_and_match_data_types(function_code, target_function="SendMessageA"):
    """
    Renames variables and matches data types to be consistent with the target function's signature.
    
    Args:
    function_code (str): A string containing the disassembly or source code.
    target_function (str): The name of the function whose data types to match (default is 'SendMessageA').
    
    Returns:
    Modified function code with renamed variables and matched data types.
    """
    # Define the mapping of argument names based on the target function
    data_types = {
        'hWnd': 'HWND',
        'Msg': 'UINT',
        'wParam': 'WPARAM',
        'lParam': 'LPARAM'
    }
    
    # Replace arguments with their appropriate data types and names
    for var, data_type in data_types.items():
        function_code = re.sub(r'\b' + var + r'\b', data_type + " " + var, function_code)
    
    # Rename function (if needed)
    function_code = re.sub(r'\b' + target_function + r'\b', 'Proxy' + target_function, function_code)
    
    # Return the modified function code
    return function_code


# Sample disassembly or function code as input (representing multiple functions calling 'SendMessageA')
function_code = """
LRESULT __stdcall SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    LRESULT LVar1;
    LVar1 = SendMessageA(hWnd, Msg, wParam, lParam);
    return LVar1;
}

void FunctionThatCallsSendMessage()
{
    SendMessageA(hWnd, Msg, wParam, lParam);
}

void AnotherFunctionThatCallsSendMessage()
{
    SendMessageA(hWnd, Msg, wParam, lParam);
}
"""

# Example usage: Find all functions calling 'SendMessageA'
calling_functions = find_calling_functions(function_code)
print("Functions that call SendMessageA:", calling_functions)

# Example usage: Rename variables and match data types in the function code
modified_function_code = rename_variables_and_match_data_types(function_code)
print("\nModified Function Code:\n", modified_function_code)
