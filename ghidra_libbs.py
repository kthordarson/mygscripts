# Starts the LibBS backend for Ghidra scripts.
# original author: LibBS
# @author kth
# @category mygscripts
# @menupath Tools.LibBS.Start LibBS Backend

import subprocess
from libbs_vendored.ghidra_bridge_server import GhidraBridgeServer

if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=True)
