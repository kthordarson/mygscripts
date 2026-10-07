# Create functions from a pointer table and name them handler_<addr>
# original author: ReverseEngineer
# @author kth
# @category mygscripts
#@keybinding
#@menupath Tools.Create Functions From Table
#@toolbar

try:
    from ghidra.ghidra_builtins import (
        createFunction,
        currentProgram,
        toAddr,
    )
except ImportError:
    pass
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()

start = toAddr(0x0042c344)
end   = toAddr(0x0042c384)

addr = start
while addr <= end:
    data = listing.getDataAt(addr)
    if data and data.isPointer():
        target = data.getValue()
        if mem.contains(target):
            if not fm.getFunctionAt(target):
                fn = createFunction(target, None)
                if fn:
                    fn.setName("handler_%X" % target.getOffset(), SourceType.USER_DEFINED)
    addr = addr.add(4)
