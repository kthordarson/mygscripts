from ghidra.program.model.data import StructureDataType, PointerDataType, CategoryPath
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import DataTypeManager, DataType, StructureDataType, PointerDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolTable
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import CodeUnit
from ghidra.program.flatapi import FlatProgramAPI

# from ghidra.program.model.code import Instruction  # 
# Common Pascal function prefixes from Lazarus/Free Pascal
PASCAL_PREFIXES = ["_P$", "SYSTEM.", "SYS_", "FPC_", "RTTI"]

def is_pascal_function(name):
    """Check if a function name matches Pascal-style naming"""
    return any(name.startswith(prefix) for prefix in PASCAL_PREFIXES)

def find_pascal_functions():
    """Find and rename Pascal-style functions"""
    symbol_table = currentProgram.getSymbolTable()

    for symbol in symbol_table.getAllSymbols(True):  # Iterate over all symbols
        if symbol.getSymbolType() == SymbolType.FUNCTION:  # Check if it's a function
            name = symbol.getName()
            if is_pascal_function(name):
                func = getFunctionAt(symbol.getAddress())
                if func:
                    print("Found Pascal function: {} at {}".format(name, func.getEntryPoint()))
                    # Optionally rename to a readable format
                    # func.setName(name.replace("_P$", ""), ghidra.program.model.symbol.SourceType.USER_DEFINED)


def create_vmt_structure(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")
    
    # Generate a unique structure name based on the address
    struct_name = "VMT_{:X}".format(addr.offset)
    
    # Create a new structure data type for the VMT
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)
    
    # Get the current listing at the address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # If there's an instruction, remove it first
    if code_unit and code_unit.getClass().getSimpleName() == "Instruction":
        print("Found instruction at " + str(addr) + ", removing it...")
        code_unit.delete()  # Remove the instruction
    
    # Now, ensure the address is free of conflicting data or instructions
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit and code_unit.getClass().getSimpleName() == "Data":
        print("Conflict detected: Data already exists at address " + str(addr))
        return
    
    # Create the VMT structure at the address
    print("Creating VMT structure at " + str(addr) + "...")
    try:
        createData(addr, struct)
        print("VMT structure created at " + str(addr))
    except Exception as e:
        print("Error creating VMT structure at " + str(addr) + ": " + str(e))


def create_vmt_structure_v12(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")
    
    # Generate a unique structure name based on the address
    struct_name = "VMT_{:X}".format(addr.offset)
    
    # Create a new structure data type
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)
    
    # Get the current listing at the address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # Check if an instruction exists at the address
    if code_unit is not None and code_unit.getClass().getSimpleName() == "Instruction":
        print("Found instruction at " + str(addr) + ", removing it...")
        code_unit.delete()  # Remove the instruction
    
    # Recheck if the address is now free of instructions
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit is not None and code_unit.getClass().getSimpleName() == "Data":
        # If there's already data, print a message and return
        print("Conflict detected: Data already exists at address " + str(addr))
        return
    
    # Create the data (VMT structure) at the address
    print("Creating VMT structure at " + str(addr) + "...")
    createData(addr, struct)
    print("VMT structure created at " + str(addr))


def create_vmt_structure_v11(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists and create a new one if not
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Get the listing at the given address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)

    # Check if there is already an instruction at this address
    if code_unit is not None:
        # If the address is already an instruction, remove it
        if code_unit.getClass().getSimpleName() == "Instruction":
            print("Found instruction at " + str(addr) + ", removing...")
            code_unit.delete()  # Remove the instruction

    # After removing any instruction, recheck the code unit at the address
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit is not None and code_unit.getClass().getSimpleName() == "Data":
        # If the address already contains data (e.g., structure), print a message and return
        print("Conflict detected: Data exists at address " + str(addr))
        return
    
    # Now, create the VMT structure at the address
    print("trying VMT structure created at {} {} ", (addr, struct))
    try:
        createData(addr, struct)
    except Exception as e:
        print('Error creating VMT structure at {}: {} {}'.format(addr, e, type(e)))

def create_vmt_structure_v10(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists and create a new one if not
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Get the listing at the given address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # If there is an instruction at the address, remove it
    if code_unit is not None:
        if code_unit.getClass().getSimpleName() == "Instruction":
            code_unit.delete()  # Remove the instruction to avoid conflicts

    # After deleting any instruction, check if we can safely create data at the address
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit is not None and code_unit.getClass().getSimpleName() == "Data":
        # If the address is already holding data (e.g., structure, array, etc.), print and return
        print("Conflict detected: Data exists at address " + str(addr))
        return
    
    # Create the VMT structure at the address
    createData(addr, struct)
    print("VMT structure created at " + str(addr))



def create_vmt_structure_v9(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists and create a new one if not
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Get the listing at the given address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # If there is an instruction at the address, remove it
    if code_unit is not None:
        if code_unit.getClass().getSimpleName() == "Instruction":
            code_unit.delete()  # Remove the instruction to avoid conflicts

    # Check again if there is code at the address
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit is None or not code_unit.isEmpty():
        # If there's code at the address, we might have to adjust the logic here
        print("Conflict detected: Code exists at address {}", addr)
        return
    
    # Create the VMT structure at the address
    createData(addr, struct)
    print("VMT structure created at {}", addr)

def create_vmt_structure_v8(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists and create a new one if not
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Get the listing at the given address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # Check if the code unit is an instruction, and remove it if so
    if code_unit is not None:
        # Check if it's an instruction
        if code_unit.getClass().getSimpleName() == "Instruction":
            code_unit.delete()  # Remove the instruction

    # Create the VMT structure at the address
    createData(addr, struct)


def create_vmt_structure_v1(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    createData(addr, struct)

def create_vmt_structure_v2(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    if code_unit and code_unit.isInstruction():  # If it's an instruction, remove it
        removeInstruction(addr)

    createData(addr, struct)

def create_vmt_structure_v3(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Fix: Check for existing code and clear it if necessary
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # Check if there's code at the address and remove it if it exists
    if code_unit is not None and code_unit.isInstruction():
        currentProgram.getCodeUnitAt(addr).delete()

    createData(addr, struct)

def create_vmt_structure_v5(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Fix: Check if the address is a code unit (instruction)
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # Check if it's an instruction, and if so, remove it
    if code_unit is not None:
        if code_unit.getMnemonic() != None:  # Check if the code unit is an instruction
            currentProgram.getCodeUnitAt(addr).delete()

    createData(addr, struct)

def create_vmt_structure_v4(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Fix: Check if the address is a code unit (instruction)
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # Check if it's an instruction, and if so, remove it
    if code_unit is not None:
        if code_unit.isInstruction():  # Check if it's an instruction
            currentProgram.getCodeUnitAt(addr).delete()  # Remove the instruction

    createData(addr, struct)

def create_vmt_structure_v6(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists and create a new one if not
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Get the listing at the given address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # Check if the code unit is an instruction, and remove it if so
    if code_unit is not None:
        if code_unit.getMnemonic() is not None:  # If it has a mnemonic, it's an instruction
            currentProgram.getCodeUnitAt(addr).delete()  # Remove the instruction

    # Create the VMT structure at the address
    createData(addr, struct)

def create_vmt_structure_v7(addr):
    """Create a Virtual Method Table (VMT) structure at the given address"""
    data_manager = currentProgram.getDataTypeManager()
    vmt_category = CategoryPath("/PascalVMT")

    struct_name = "VMT_{:X}".format(addr.offset)
    struct = StructureDataType(vmt_category, struct_name, 0)
    struct.add(PointerDataType(), 8, "MethodPtr1", "")
    struct.add(PointerDataType(), 8, "MethodPtr2", "")
    struct.add(PointerDataType(), 8, "MethodPtr3", "")
    struct.add(PointerDataType(), 8, "MethodPtr4", "")

    # Check if structure already exists and create a new one if not
    existing_struct = data_manager.getDataType(vmt_category, struct_name)
    if not existing_struct:
        data_manager.addDataType(struct, None)

    # Get the listing at the given address
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    
    # Check if the code unit is an instruction, and remove it if so
    if code_unit is not None:
        # Directly checking if it's an instruction by looking at its type
        if isinstance(code_unit, Instruction):  # Check if it's an instruction
            code_unit.delete()  # Remove the instruction

    # Create the VMT structure at the address
    createData(addr, struct)


def find_vmt_tables():
    """Find and create structures for Virtual Method Tables (VMTs)"""
    for block in currentProgram.getMemory().getBlocks():
        if not block.isExecute():
            continue
        
        addr = block.getStart()
        while addr < block.getEnd():
            refs = getReferencesTo(addr)
            if len(refs) > 5:  # VMT tables usually have many references
                print("Potential VMT table at: {}".format(addr))
                try:
                    create_vmt_structure(addr)
                except Exception as e:
                    print('Error creating VMT structure at {}: {} {}'.format(addr, e, type(e)))
            addr = addr.add(8)

def run():
    print("\n--- Recovering Pascal Function Names ---\n")
    find_pascal_functions()
    
    print("\n--- Searching for Virtual Method Tables (VMTs) ---\n")
    find_vmt_tables()
    
    print("\n--- Pascal Type Recovery Completed ---\n")

run()
