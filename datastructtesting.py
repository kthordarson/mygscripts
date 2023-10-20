from ghidra.program.model.data import StructureDataType, CategoryPath, DataTypeConflictHandler, PointerDataType, BuiltInDataTypeManager, ArrayDataType
from ghidra.program.model.data import StructureFactory
import re
import struct
from collections import namedtuple, defaultdict
FoundPointer = namedtuple("FoundPointer", ["points_to", "location"])

class FoundVTable:
    def __init__(self, address, pointers=None):
        self.address = address
        if pointers is not None:
            self.pointers = pointers
        else:
            self.pointers = []
        self.associated_struct = None
    @property
    def size(self):
        return len(self.pointers)

    def __repr__(self):
        return "FoundVTable(address=%s, size=%d)" % (str(self.address), self.size)


bdm = BuiltInDataTypeManager.getDataTypeManager()
dm = currentProgram().getDataTypeManager()
namespace_manager = currentProgram().getNamespaceManager()


addr_fact = currentProgram().getAddressFactory()
addr_space = addr_fact.getDefaultAddressSpace()
mem = currentProgram().getMemory()
little_endian = not mem.isBigEndian()
sym_tab = currentProgram().getSymbolTable()
_stack_reg_offset = currentProgram().getRegister("sp").getOffset()
struct_fact = StructureFactory()
listing = currentProgram().getListing()
bm = currentProgram().getBookmarkManager()
ptr_size = addr_space.getPointerSize()
pack_endian = "<"
is_64_bit = False
_get_ptr_size = mem.getInt
pack_code = "I"
pack_sym = pack_endian + pack_code


memory_blocks = list(getMemoryBlocks())
memory_blocks_ = [k for k in getMemoryBlocks()]
excluded_memory_block_names=["tdb"]

search_memory_blocks = [i for i in memory_blocks if i.getPermissions() == i.READ]


# test
# m_block = [k for k in getMemoryBlocks()][0]
m_block =  [k for k in getMemoryBlocks()][2]
region_start = [k for k in getMemoryBlocks()][2].getStart()
region_start_int = region_start.getOffset()

search_bytes = getBytes(region_start, m_block.getSize())
# or
# search_bytes = [k for k in getBytes(region_start, m_block.getSize())]
# or
search_bytes = getBytes(region_start, m_block.getSize()).toString()
#minimum_addr = 552992768
#maximum_addr = 553136127
minimum_addr = 0x004262a8
maximum_addr = 0x00429548
diff = maximum_addr - minimum_addr
val = diff
byte_count = 0
while val > 0:
	val = val >> 8
	byte_count += 1
# byte_count = 3
wildcard_bytes = byte_count - 1

address_pattern = b'([\x00-\xff][\x00-\xff][\\\xf6-\\\xf8] )+'
boundary_byte_pattern = b'[\\\xf6-\\\xf8]'
wildcard_pattern = b"[\x00-\xff]"
single_address_pattern = b''
packed_addr = struct.pack(pack_sym, minimum_addr)
single_address_pattern = b''.join([wildcard_pattern*wildcard_bytes, boundary_byte_pattern, packed_addr[byte_count:]])
address_pattern = b"(%s)+" % single_address_pattern
# = b'([\x00-\xff][\x00-\xff][\\\xf6-\\\xf8] )+'
# address_pattern = b'([\x00-\xff][\\\xf6-\\\xf8]B\x00)+'
address_rexp = re.compile(b'([\x00-\xff][\x00-\xff][\\\xf6-\\\xf8] )+', re.MULTILINE|re.DOTALL)
address_rexp = re.compile("b'([\\x00-\\xff][\\x00-\\xff][\\\\@-\\\\T]\\x00)+'", re.MULTILINE|re.DOTALL)
# works ... re.findall('([\x00-\xff])+', search_bytes)
# works ... re.findall('([\x00-\xff][\x00-\xff])+', search_bytes)
# works ... re.findall('([\x00-\xff][\x00-\xff]{10})+', search_bytes) = ['[B@54f587b4']
# iter_gen = re.finditer('([\x00-\xff][\x00-\xff]{10})+', search_bytes)
iter_gen = re.finditer(address_rexp, bytes(search_bytes.toString(), 'utf8'))
iter_gen = address_rexp.finditer(bytes(search_bytes.toString(),'utf8'))
####
iter_gen = re.finditer(address_rexp, bytes(search_bytes.toString(), 'utf8'))

vtable_match_bytes = '[B@54f587b4'
unpacked_addr_ints = struct.unpack_from(pack_endian + (len(vtable_match_bytes)//ptr_size)*pack_code, vtable_match_bytes)
unpacked_addr_ints =  struct.unpack_from(pack_endian + (len(vtable_match_bytes)//ptr_size)*pack_code, bytes(vtable_match_bytes,'utf8'))

addr_val = [k for k in unpacked_addr_ints][0]
match_start = m.start()
location_int = region_start_int + match_start + (ptr_size)
location = addr_space.getAddress(location_int)
FoundPointer(addr_space.getAddress(addr_val), location)

found_pointers = []
found_pointers.append(FoundPointer(addr_space.getAddress(addr_val), location))
location_refs = getReferencesTo(found_pointer.location)