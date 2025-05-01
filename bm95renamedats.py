from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Program
from ghidra.util.task import TaskMonitor

# Dictionary mapping addresses to new variable names
variable_mappings = {
    0x004a218e: "tile_218e_id",
    0x004a2190: "tile_2190_id",
    0x004a2192: "tile_2192_flag",
    0x004a2194: "tile_2194_flag",
    0x004a2196: "tile_2196_flag",
    0x004a23ae: "object_23ae_flag",
    0x004a23b0: "object_23b0_flag",
    0x004a23b2: "object_23b2_flag",
    0x004a1fbe: "object_1fbe_flag",
    0x004a1fc0: "object_1fc0_flag",
    0x004a1fc2: "object_1fc2_flag",
    0x004a1fca: "tile_1fca_flag",
    0x004a1fcc: "tile_1fcc_flag",
    0x004a1fce: "tile_1fce_flag",
    0x004a1fd6: "tile_1fd6_flag",
    0x004a1fd8: "tile_1fd8_flag",
    0x004a1fda: "tile_1fda_flag",
    0x004a1ffa: "tile_1ffa_flag",
    0x004a1ffc: "tile_1ffc_flag",
    0x004a1ffe: "tile_1ffe_flag",
    0x004a2006: "tile_2006_flag",
    0x004a2008: "tile_2008_flag",
    0x004a200a: "tile_200a_flag",
    0x004a2012: "tile_2012_flag",
    0x004a2014: "tile_2014_flag",
    0x004a2016: "tile_2016_flag",
    0x004a201e: "tile_201e_flag",
    0x004a2020: "tile_2020_flag",
    0x004a2022: "tile_2022_flag",
    0x004a202a: "tile_202a_flag",
    0x004a202c: "tile_202c_flag",
    0x004a202e: "tile_202e_flag",
    0x004a2036: "tile_2036_flag",
    0x004a2038: "tile_2038_flag",
    0x004a203a: "tile_203a_flag",
    0x004a2042: "tile_2042_flag",
    0x004a2044: "tile_2044_flag",
    0x004a2046: "tile_2046_flag",
    0x004a20de: "tile_20de_flag",
    0x004a20e0: "tile_20e0_id",
    0x004a20e2: "tile_20e2_flag",
    0x004a20ea: "tile_20ea_flag",
    0x004a20ee: "tile_20ee_flag",
    0x004a217a: "tile_217a_flag",
    0x004a217e: "tile_217e_flag",
    0x004a23aa: "object_23aa_id",
    0x004a23ac: "object_23ac_id",
    0x004a20ec: "tile_20ec_id",
    0x004a1fba: "object_1fba_id",
    0x004a1fbc: "object_1fbc_id",
    0x004a217c: "tile_217c_id",
    0x004a1fc6: "tile_1fc6_id",
    0x004a1fc8: "tile_1fc8_id",
    0x004a1fd2: "tile_1fd2_id",
    0x004a1fd4: "tile_1fd4_id",
    0x004a1ff6: "tile_1ff6_id",
    0x004a1ff8: "tile_1ff8_id",
    0x004a2002: "tile_2002_id",
    0x004a2004: "tile_2004_id",
    0x004a200e: "tile_200e_id",
    0x004a2010: "tile_2010_id",
    0x004a201a: "tile_201a_id",
    0x004a201c: "tile_201c_id",
    0x004a2026: "tile_2026_id",
    0x004a2028: "tile_2028_id",
    0x004a2032: "tile_2032_id",
    0x004a2034: "tile_2034_id",
    0x004a203e: "tile_203e_id",
    0x004a2040: "tile_2040_id",
    0x004a20da: "tile_20da_id",
    0x004a20dc: "tile_20dc_id",
    0x004a20e6: "tile_20e6_id",
    0x004a20e8: "tile_20e8_id",
    0x004a2176: "event_2176_code",
    0x004a2178: "event_2178_code",
    0x004a2186: "tile_2186_flag",
    0x004a2182: "event_2182_code",
    0x004a2184: "event_2184_code",
    0x004a21a6: "event_21a6_code",
    0x004a21aa: "tile_21aa_flag",
    0x004a21ac: "tile_21ac_flag",
    0x004a21ae: "tile_21ae_flag",
    0x004a2188: "tile_2188_id",
    0x004a21a8: "tile_21a8_id",
    0x004a218a: "tile_218a_flag",
    0x004a1fa4: "position_data_base",
    0x004a1fa6: "position_data_1fa6",
    0x004a1fa8: "position_data_1fa8",
    0x004a1faa: "position_data_1faa"
}

def rename_dat_variables():
    # Get the current program
    program = currentProgram
    symbol_table = currentProgram().getSymbolTable()
    memory = program().getMemory()
    monitor = TaskMonitor.DUMMY

    print("Starting DAT_ and _DAT variable renaming...")

    for addr_value, new_name in variable_mappings.items():
        # Create an address object
        addr = program().getAddressFactory().getAddress(hex(addr_value))
        if addr is None:
            print("Invalid address: {}".format(hex(addr_value)))
            continue

        # Get existing symbol at the address
        symbols = symbol_table.getSymbols(addr)
        existing_symbol = None
        for symbol in symbols:
            if symbol.getName().startswith("DAT_") or symbol.getName().startswith("_DAT_"):
                existing_symbol = symbol
                break

        # Rename or create symbol
        if existing_symbol is not None:
            print("Renaming {} to {} at {}".format(existing_symbol.getName(), new_name, addr))
            existing_symbol.setName(new_name, SourceType.USER_DEFINED)
        else:
            # Create a new symbol if none exists
            print("Creating new symbol {} at {}".format(new_name, addr))
            symbol_table.createLabel(addr, new_name, True, SourceType.USER_DEFINED)

    print("Variable renaming completed.")

if __name__ == "__main__":
    rename_dat_variables()