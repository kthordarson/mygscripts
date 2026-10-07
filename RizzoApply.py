# Apply "fuzzy" function signatures from a different Ghidra project.

# @author kth
# @category mygscripts
# @menupath kthtools.Rizzo.Apply Signatures


try:
    from ghidra.ghidra_builtins import (
        askFile,
        currentProgram,
    )
except ImportError:
    pass
from utils import rizzo

file_path = askFile('Load signature file', 'OK').path

print('Applying Rizzo signatures, this may take a few minutes...')

rizz = rizzo.Rizzo(currentProgram)
signatures = rizz.load(file_path)
rizz.apply(signatures)
