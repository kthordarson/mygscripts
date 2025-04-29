# Import necessary Ghidra classes
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import Symbol
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.listing import CodeUnit, Instruction, Data
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SymbolType

import sys
import logging

# Open a file for logging output
log_file = "c:/apps/temp/ghidra_script_output.txt"
# sys.stdout = log_file  # Redirect stdout to the log file
logging.basicConfig(filename=log_file, level=logging.DEBUG,    format="%(asctime)s - %(levelname)s - %(message)s")

def find_address_tables():
    """
    This function searches for address tables in the program by looking for sequences of address-like data.
    It detects 4-byte or 8-byte address values that could represent function address tables.
    """
    # Get the current program's listing
    listing = currentProgram.getListing()
    address_table = []
    
    # Iterate through all code units in the listing
    code_units = listing.getCodeUnits(True)  # Iterate through the code units (data/code) in the program

    for code_unit in code_units:
        if isinstance(code_unit, Data):  # Only process data units
            # Check if the data unit is a series of 4-byte or 8-byte values (potential address table)
            data_type = code_unit.getDataType()            
            # Check for 4-byte or 8-byte integers (likely address pointers)
            if data_type.getLength() == 4 or data_type.getLength() == 8:
                # We assume that the data unit contains an address
                value = code_unit.getValue()                
                try:
                    # If the value is an address, convert it to an integer
                    if isinstance(value, Address):
                        value_int = value.getOffset()
                    else:
                        try:
                            value_int = int(value)                    
                        except TypeError as e:
                            print("Error converting value to int at %s: %s %s" % (code_unit.getAddress(), str(e), type(e)))
                            continue
                    if value_int:
                        # Add this address to our address table
                        address_table.append((code_unit.getAddress(), value_int))                
                except Exception as e:
                    print("Error processing value at %s: %s %s" % (code_unit.getAddress(), str(e), type(e)))
                    continue
        else:
            pass  # logging.warning("Skipping non-address data type: %s at %s" % (data_type.getName(), code_unit.getAddress()))

    # Print out the detected address table entries
    if address_table:
        print("Found %d potential address table entries:" % len(address_table))
        for addr, value in address_table:
            logging.info("Address: %s -> Value: %s" % (addr, value))
            # print("Address: %s -> Value: %s" % (addr, hex(value)))
    else:
        print("No address tables found in the program.")


def create_function_from_lab_address(function_name, lab_address):
    """
    Creates a function at the specified lab address if not already existing.
    """
    function_manager = currentProgram.getFunctionManager()
    
    # Check if a function already exists at this address
    existing_function = function_manager.getFunctionAt(lab_address)
    if existing_function is None:
        # Create a new function at the lab address
        function_manager.createFunction(function_name, lab_address, SourceType.USER_DEFINED)
        print("Function created: ", function_name, "at", lab_address)
    else:
        print("Function already exists at ", lab_address, ":", existing_function.getName())


def find_function_address_tables():
    """
    Finds all function address tables in the program and creates functions for
    each entry starting with 'LAB_'.
    """
    # Access the program's memory
    memory = currentProgram.getMemory()
    
    # Get the symbol table and find all function address tables
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getAllSymbols(True)
    # print("Total symbols found: ", len(symbol_table))
    # Iterate over all symbols to find function address tables
    for symbol in symbols:
        # We are looking for function address tables, typically these are arrays of function pointers
        print("Symbol: ", symbol.getName())
        if symbol.getName().lower().startswith("f_") and symbol.getDataType().getName() == "pointer":
            print("Found function address table: ", symbol.getName())
            #  {symbol.getName()} at {symbol.getAddress()}
            # Scan through the table and look for function addresses starting with "LAB_"
            table_address = symbol.getAddress()
            num_entries = symbol.getDataType().getLength() // 4  # assuming 4-byte addresses
            
            for i in range(num_entries):
                func_address = table_address.add(i * 4)  # each entry is 4 bytes
                func_address_value = memory.getInt(func_address)
                
                # Check if the address is a valid function address and starts with 'LAB_'
                if func_address_value != 0 and currentProgram.getFunctionManager().getFunctionAt(func_address_value) is None:
                    # Check if the function address matches a 'LAB_' pattern
                    if currentProgram.getMemory().getByte(func_address_value) == ord('L'):
                        # Create the function at the address
                        lab_name = "LAB_" + func_address_value.getOffset()
                        create_function_from_lab_address(lab_name, func_address_value)


def find_lab_labels():
    """
    This function searches for `LAB_` labels in the disassembly.
    It checks if the label is potentially a function entry point.
    """
    # Get the current program's listing and symbol table
    listing = currentProgram.getListing()
    symbol_table = currentProgram.getSymbolTable()
    
    lab_labels = []
    
    # Iterate through all symbols in the symbol table
    for symbol in symbol_table.getAllSymbols(True):
        # Check if the symbol is a label and its name starts with 'LAB_'
        if symbol.getSymbolType() == SymbolType.LABEL and symbol.getName().startswith("LAB_"):
            # Get the address of the symbol (label)
            label_address = symbol.getAddress()
            
            # Check if it's a valid code unit (function entry or jump target)
            code_unit = listing.getCodeUnitAt(label_address)
            
            if code_unit:
                # Ensure we check if the code unit is an instruction
                if isinstance(code_unit, Instruction):
                    # Get the mnemonic of the instruction
                    mnemonic = code_unit.getMnemonicString()
                    
                    # Check if it's a jump or call instruction (potential function entry)
                    if mnemonic in ["CALL", "JMP", "JMP FAR"]:
                        lab_labels.append(symbol)
    
    # If we found any LAB_ labels, print them
    if lab_labels:
        print("Found {} LAB_ labels:".format(len(lab_labels)))
        for symbol in lab_labels:
            print("Label: {} at {}".format(symbol.getName(), symbol.getAddress()))
    else:
        print("No LAB_ labels found in the program.")


def find_undefined_lab_functions():
    """
    Searches for undefined functions that start with 'LAB_'.
    These are typically function entry points marked with labels in the disassembly.
    """
    # Access the program's function manager
    function_manager = currentProgram.getFunctionManager()
    
    # Get the listing of all functions in the program
    functions = function_manager.getFunctions(True)
    
    # List to keep track of functions that start with LAB_
    lab_functions = []
    
    # Iterate through all functions to find those that start with LAB_
    for function in functions:
        # Check if the function name starts with 'LAB_' (common naming convention for undefined functions)
        if function.getName().startswith("LAB_"):
            # Add to list of LAB_ functions
            lab_functions.append(function)
    
    # If we found any LAB_ functions, print them
    if lab_functions:
        print("Found {} undefined LAB_ functions:", len(lab_functions))
        for func in lab_functions:
            print("Function: ", func.getName(), "at", func.getEntryPoint())
            # print(f"Function: {func.getName()} at {func.getEntryPoint()}")
    else:
        print("No LAB_ functions found in the program.")

# Main execution
find_address_tables()


