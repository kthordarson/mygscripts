#Highlight or un-highlight function calls.
# original author: fuzzywalls
# @author kth
# @category mygscripts
#@menupath TNS.Un/Highlight Function Calls


try:
    from ghidra.ghidra_builtins import (
        askChoice,
        clearBackgroundColor,
        currentProgram,
        setBackgroundColor,
    )
except ImportError:
    pass
from java.awt import Color
from ghidra.program.model.symbol import RefType

answer = askChoice('Highlight?',
                   'Highlight or un-highlight function calls?',
                   ['highlight', 'un-highlight'],
                   'highlight')

# Dull yellow color.
highlight_color = Color(250, 250, 125)

code_manager = currentProgram().getCodeManager()
image_base = currentProgram().getImageBase()

instructions = code_manager.getInstructions(image_base, True)

for ins in instructions:
    if ins.getFlowType().isCall():
        if answer == 'highlight':
            setBackgroundColor(ins.getAddress(), highlight_color)
        else:
            clearBackgroundColor(ins.getAddress())
