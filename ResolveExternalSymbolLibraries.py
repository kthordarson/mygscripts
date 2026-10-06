# Move individual external symbols currently sitting under the "<EXTERNAL>"
# (Library.UNKNOWN) namespace into the namespace of whichever linked library
# Program actually defines/exports that name, so the Symbol Tree "Imports"
# view groups them under the right .so instead of all under <EXTERNAL>.
#
# Requires the library-name -> Program associations to already be set
# (e.g. via AutoResolveExternalLibraries.py) so ext_manager.getExternalLibraryPath()
# resolves for each linked library.
#
# A function only counts as a real "export" of a library if it has a body
# and is NOT itself a thunk to an external location - otherwise every
# library's own PLT stubs for common libc calls (strcmp, memcpy, ...) would
# falsely look like they "define" those names too.
#
# @category ImportUtils

UNKNOWN_LIBRARY_NAME = "<EXTERNAL>"


def build_export_name_set(target_program):
    names = set()
    fm = target_program.getFunctionManager()
    for f in fm.getFunctions(True):
        if f.isExternal() or f.isThunk():
            continue
        names.add(f.getName())
    st = target_program.getSymbolTable()
    for sym in st.getAllSymbols(True):
        if sym.isExternal():
            continue
        obj = sym.getObject()
        if obj is not None and hasattr(obj, "isThunk") and obj.isThunk():
            continue
        names.add(sym.getName())
    return names


def run():
    program = currentProgram
    ext_manager = program.getExternalManager()
    st = program.getSymbolTable()
    project_data = state.getProject().getProjectData()

    lib_names = [n for n in ext_manager.getExternalLibraryNames() if n != UNKNOWN_LIBRARY_NAME]

    opened = []
    name_to_libs = {}

    for lib_name in lib_names:
        path = ext_manager.getExternalLibraryPath(lib_name)
        if not path:
            print("Skipping {} - no associated project program set yet".format(lib_name))
            continue
        df = project_data.getFile(path)
        if df is None:
            print("Could not locate project file for path: {}".format(path))
            continue
        try:
            dobj = df.getDomainObject(program, False, False, monitor)
        except Exception as e:
            print("Failed to open {}: {}".format(path, e))
            continue
        opened.append(dobj)
        try:
            for name in build_export_name_set(dobj):
                name_to_libs.setdefault(name, set()).add(lib_name)
        except Exception as e:
            print("Failed to index exports of {}: {}".format(lib_name, e))

    moved = []
    failed = []
    ambiguous = []
    still_unknown = []

    ext_syms = list(st.getExternalSymbols())
    for sym in ext_syms:
        parent = sym.getParentNamespace()
        if parent is None or parent.getName() != UNKNOWN_LIBRARY_NAME:
            continue
        name = sym.getName()
        libs = name_to_libs.get(name)
        if not libs:
            still_unknown.append(name)
            continue
        if len(libs) > 1:
            ambiguous.append("{} found in multiple libs: {}".format(name, sorted(libs)))
            continue
        target_lib_name = next(iter(libs))
        try:
            target_ns = ext_manager.getExternalLibrary(target_lib_name)
            sym.setNamespace(target_ns)
            moved.append("{} -> {}".format(name, target_lib_name))
        except Exception as e:
            failed.append("{} -> {} : {}".format(name, target_lib_name, e))

    for dobj in opened:
        dobj.release(program)

    print("=== Moved into correct library namespace ({}) ===".format(len(moved)))
    for line in moved:
        print("  " + line)

    if failed:
        print("=== Failed to move (exception) ({}) ===".format(len(failed)))
        for line in failed:
            print("  " + line)

    print("=== Ambiguous - same name exported by multiple linked libs ({}) ===".format(len(ambiguous)))
    for line in ambiguous:
        print("  " + line)

    print("=== Still under <EXTERNAL>, name not found in any linked library ({}) ===".format(len(still_unknown)))
    for line in still_unknown[:60]:
        print("  " + line)
    if len(still_unknown) > 60:
        print("  ... and {} more".format(len(still_unknown) - 60))


run()
