# Toggle gray background highlight on code blocks
# @author kth
# @category mygscripts
try:
    from ghidra.ghidra_builtins import (
        clearBackgroundColor,
        monitor,
        setBackgroundColor,
    )
except ImportError:
    pass
def color_block(block):
  if service:
      color = service.getBackgroundColor(block.getFirstStartAddress())
      if color and color.getBlue() == 128:
          clearBackgroundColor(block)
      else:
          clearBackgroundColor(block)
          setBackgroundColor(block, Color.GRAY)


def highlight_blocks(model, addrs):

  for addr in addrs:
      print (addr)
      b = model.getCodeBlockAt(addr, monitor)
      print ("block: ", b)
      if b:
          color_block(b)

