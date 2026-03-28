#@author kth
#@category mygscripts
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra


#TODO Add User Code Here

# Ghidra script: Convert all ASCII regions to strings automatically
# This will scan the entire memory and convert any printable sequences into strings.

from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import DataTypeConflictHandler
import string

def is_printable_ascii(byte_array):
    try:
        text = byte_array.decode('ascii')
        return all(c in string.printable for c in text)
    except:
        return False

memory = currentProgram.getMemory()
listing = currentProgram.getListing()

print("Scanning memory for ASCII strings...")

for block in memory.getBlocks():
    start = block.getStart()
    end = block.getEnd()
    addr = start

    while addr < end:
        # Read up to 256 bytes at a time
        length = min(256, end.subtract(addr) + 1)
        bytes_data = getBytes(addr, length)

        # Find printable sequences
        for i in range(length):
            for j in range(i+4, length):  # Minimum length = 4 chars
                segment = bytes_data[i:j]
                if is_printable_ascii(segment):
                    str_addr = addr.add(i)
                    str_text = segment.decode('ascii')
                    
                    # Create string data type in Ghidra
                    try:
                        createAsciiString(str_addr)
                        print("Created string at {}: {}".format(str_addr, str_text))
                    except:
                        pass
        addr = addr.add(length)

print("String conversion completed.")