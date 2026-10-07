# A cross-decompiler collaboration plugin
# original author: BinSync Team
# @author kth
# @category mygscripts
# @menupath Tools.BinSync.Connect...
# @runtime PyGhidra

def create_plugin(*args, **kwargs):
    # REPLACE_ME this import with an import of your plugin's create_plugin function
    from binsync import create_plugin as _create_plugin
    return _create_plugin(*args, **kwargs)

# =============================================================================
# LibBS generic plugin loader (don't touch things below this)
# =============================================================================


def PLUGIN_ENTRY(*args, **kwargs):
    """
    This is the entry point for IDA to load the plugin.
    """
    return create_plugin(*args, **kwargs)

try:
    import idaapi  # type: ignore
    HAS_IDA = True
except ImportError:
    HAS_IDA = False

if not HAS_IDA:
    create_plugin()
