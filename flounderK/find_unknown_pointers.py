# Find undefined data that looks like pointers into program memory and type it as pointers
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        createTableChooserDialog,
        currentProgram,
        getFunctionContaining,
        getMemoryBlocks,
        state,
        toAddr,
        findBytes
    )
except ImportError:
    pass
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import PointerDataType
import struct
import re
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


def applyDataTypeAtAddress(address, datatype, size=None, program=None):
    if program is None:
        program = currentProgram
    if size is None:
        size = datatype.getLength()
    listing = program.getListing()
    listing.clearCodeUnits(address, address.add(size), False)
    listing.createData(address, datatype, size)


def gen_address_range_rexp(minimum_addr, maximum_addr, program=None):
    if program is None:
        program = currentProgram

    ptr_size = program.getDefaultPointerSize()
    mem = program.getMemory()
    is_big_endian = mem.isBigEndian()
    ptr_pack_sym = ""
    if ptr_size == 4:
        ptr_pack_sym = "I"
    elif ptr_size == 8:
        ptr_pack_sym = "Q"

    pack_endian = ""
    if is_big_endian:
        pack_endian = ">"
    else:
        pack_endian = "<"
    ptr_pack_code = pack_endian + ptr_pack_sym

    # java.math.BigInteger doesn't support python operators or int(),
    # convert via its decimal string representation
    minimum_addr = int(str(minimum_addr))
    maximum_addr = int(str(maximum_addr))
    diff = maximum_addr - minimum_addr
    val = diff
    # calculate the changed number of bytes between the minimum_addr and the maximum_addr
    byte_count = 0
    while val > 0:
        val = val >> 8
        byte_count += 1
    # a range within a single byte value still needs one boundary byte
    byte_count = max(byte_count, 1)

    # generate a sufficient wildcard character classes for all of the bytes that could fully c
    wildcard_bytes = byte_count - 1
    wildcard_pattern = "[\\x00-\\xff]"
    boundary_byte_upper = (maximum_addr >> (wildcard_bytes * 8)) & 0xFF
    boundary_byte_lower = (minimum_addr >> (wildcard_bytes * 8)) & 0xFF
    if boundary_byte_upper < boundary_byte_lower:
        boundary_byte_upper, boundary_byte_lower = (
            boundary_byte_lower,
            boundary_byte_upper,
        )
    # create a character class that will match the largest changing byte
    # lower_byte = bytearray([boundary_byte_lower])
    # upper_byte = bytearray([boundary_byte_upper])
    boundary_byte_pattern = "[\\x%02x-\\x%02x]" % (
        boundary_byte_lower,
        boundary_byte_upper,
    )
    address_pattern = ""
    single_address_pattern = ""
    packed_addr = struct.pack(ptr_pack_code, minimum_addr)
    if not is_big_endian:
        # low bytes first: wildcards, boundary byte, then the fixed high bytes
        single_address_pattern = "".join(
            [wildcard_pattern * wildcard_bytes, boundary_byte_pattern]
        )
        for i in packed_addr[byte_count:]:
            single_address_pattern += "\\x%02x" % i
    else:
        # high bytes first: fixed high bytes, boundary byte, then wildcards
        for i in packed_addr[: ptr_size - byte_count]:
            single_address_pattern += "\\x%02x" % i
        single_address_pattern += "".join(
            [boundary_byte_pattern, wildcard_pattern * wildcard_bytes]
        )
    address_pattern = "(%s)" % single_address_pattern
    return address_pattern


def create_full_memory_rexp(program=None):
    if program is None:
        program = currentProgram
    patterns = []
    # get an address set for all current memory blocks
    for m_block in getMemoryBlocks():
        start = m_block.start.getOffsetAsBigInteger()
        end = m_block.end.getOffsetAsBigInteger()
        pat = gen_address_range_rexp(start, end)
        # log.debug("adding pattern '%s'" % pat)
        patterns.append(pat)

    full_pat = "(%s)" % "|".join(patterns)
    log.debug("full pattern '%s' total patterns: %d" % (full_pat, len(patterns)))
    return full_pat


def create_full_mem_addr_set():
    existing_mem_addr_set = AddressSet()
    for m_block in getMemoryBlocks():
        existing_mem_addr_set.add(m_block.getAddressRange())
    return existing_mem_addr_set


def find_full_mem_pointers(program=None, align_to=4):
    if program is None:
        program = currentProgram
    existing_mem_addr_set = create_full_mem_addr_set()
    full_pat = create_full_memory_rexp(program=program)
    for addr in findBytes(existing_mem_addr_set, full_pat, 100000, align_to):
        yield addr


def identify_unknown_pointers(program=None, align_to=4):
    if program is None:
        program = currentProgram
    # default (void) pointer sized to the program
    ptr_dt = PointerDataType(None, -1, program.getDataTypeManager())
    listing = program.getListing()
    for addr in find_full_mem_pointers(program=program, align_to=align_to):

        if addr.getOffset() % align_to != 0:
            continue
        # getCodeUnitContaining also returns undefined data, so check for
        # instructions specifically
        def_code = listing.getInstructionContaining(addr)
        if def_code is not None:
            log.warning("match in code at %s" % addr)
            continue

        # getDataContaining also returns undefined data, only skip defined data
        def_dat = listing.getDefinedDataContaining(addr)
        # skip defined data
        if def_dat is not None:
            continue
        # log.info("found data at %s" % addr)
        applyDataTypeAtAddress(addr, ptr_dt)


if __name__ == "__main__":
    identify_unknown_pointers()
