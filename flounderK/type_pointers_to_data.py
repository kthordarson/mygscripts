# This script identifies locations where data values embedded in a binary
# can be represented as addresses, but the type of those embedded data objects
# is either undefined or is defined as a generic pointer. It then appropriatly
# types them
#
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
    )
except ImportError:
    pass
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import Pointer
from ghidra.program.model.data import TypeDef
from ghidra.program.model.data import TypedefDataType
from ghidra.program.model.data import ComponentOffsetSettingsDefinition
from ghidra.program.model.scalar import Scalar
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


# get an address set for all current memory blocks
existing_mem_addr_set = AddressSet()
for m_block in getMemoryBlocks():
    # cut sections that are unused
    if not (m_block.isRead() or m_block.isWrite() or m_block.isExecute()):
        continue
    existing_mem_addr_set.add(m_block.getAddressRange())


dtm = currentProgram.getDataTypeManager()
useful_dat = []
listing = currentProgram.getListing()
for dat in listing.getDefinedData(1):
    addr_repr = None
    # handle undefined datatype
    if dat.valueClass is None:
        val = dat.value
        if val is None:
            # log.debug("skipping undefined data with no value at %s" % dat)
            continue
        int_val = val.getUnsignedValue()
        addr_repr = toAddr(int_val)
    # handle all pointer datatypes
    if dat.isPointer():
        val = dat.value
        if val is None:
            # log.debug("skipping pointer data with no value at %s" % dat)
            continue
        # TODO: detect type pointed to
        int_val = val.getOffsetAsBigInteger()
        addr_repr = val
    # handle other scalar values, (uint, int, etc.)
    if isinstance(dat.value, Scalar):
        addr_repr = toAddr(dat.value.value)
    if addr_repr is None:
        # log.debug("skipping data with no address representation at %s" % dat)
        continue

    # find all of the defined data in the program that could
    # be a pointer to the current model of memory
    if not existing_mem_addr_set.contains(addr_repr):
        # log.debug("skipping data pointing outside of existing memory at %s" % dat)
        continue
    useful_dat.append(dat)
    curr_dt = dat.dataType
    dat_cont = listing.getDataContaining(addr_repr)
    if dat_cont is None:
        # log.debug("no data containing address %s found" % addr_repr)
        continue
    if dat_cont.isStructure() is False:
        # log.debug("data containing address %s is not a structure" % addr_repr)
        continue

    # apply datatype if addresses matches to start of defined data
    if dat_cont.address == addr_repr:
        new_type = dtm.getPointer(dat_cont.dataType)
        if curr_dt != new_type:
            log.debug("setting type at %s" % dat)
            applyDataTypeAtAddress(dat.address, new_type)
        continue

    # if address didn't match, it means that a pointer offset typedef
    # needs to be used.
    # iterate through existing typedefs to see if one already exists
    # that will work correctly
    typedef_dts = [dt for dt in dtm.getAllDataTypes() if isinstance(dt, TypeDef)]
    off = addr_repr.subtract(dat_cont.address)
    set_typedef_dt = None
    for dt in typedef_dts:
        pointed_dt = dt.dataType
        # only care about typedefs to pointers, so skip the rest
        if not isinstance(pointed_dt, Pointer):
            continue
        if pointed_dt.dataType != dat_cont.dataType:
            continue
        comp_off = dt.defaultSettings.getValue("component_offset")
        if comp_off is None:
            continue
        if comp_off == off:
            log.debug("found matching type for %s" % dat_cont.dataType.name)
            set_typedef_dt = dt
            break

    log.debug("setting type to offser pointer at %s" % dat.address)
    if set_typedef_dt is None:
        log.debug("making a new datatype for %s %d" % (dat_cont.dataType.name, off))
        # if there wasn't a match, make a new typedef
        new_typedef_name = "%s_ptr_%d" % (dat_cont.dataType.name, off)
        ptr_type = dtm.getPointer(dat_cont.dataType)
        new_typedef = TypedefDataType(new_typedef_name, ptr_type)
        set_typedef_dt = dtm.resolve(new_typedef, None)
        default_settings = set_typedef_dt.getDefaultSettings()
        ComponentOffsetSettingsDefinition.DEF.setValue(default_settings, off)
    applyDataTypeAtAddress(dat.address, set_typedef_dt)

