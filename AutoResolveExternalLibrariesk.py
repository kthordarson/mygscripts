# Auto-resolve unresolved external Library imports to matching Programs
# already present elsewhere in the same Ghidra project, so cross-references
# and decompilation follow into the real library code without manual
# drag-and-drop of each entry under the Imports tree.
#
# Matching strategy per unresolved library name (e.g. "libz.so.1" as recorded
# in the ELF DT_NEEDED entry):
#   1. exact DomainFile name match anywhere in the project
#   2. versioned match: a project file whose name starts with "<libname>."
#      (handles SONAME vs on-disk filename mismatches, e.g. import
#      "libcJSON.so" -> project file "libcJSON.so.1.7.14")
# If multiple versioned candidates exist (e.g. two libz.so.1.x.y files),
# picks the alphabetically-last one and reports all candidates so you can
# override manually if it picked the wrong one.
#
# @author kth
# @category mygscripts

try:
    from ghidra.ghidra_builtins import (
        currentProgram,
        state,
    )
except ImportError:
    pass
UNKNOWN_LIBRARY_NAME = "<EXTERNAL>"


def collect_all_files(folder, out, seen):
    if folder in seen:
        return
    seen.add(folder)
    for df in folder.getFiles():
        out.append(df)
    for sub in folder.getFolders():
        collect_all_files(sub, out, seen)


def find_candidates(all_files, lib_name):
    exact = [df for df in all_files if df.getName() == lib_name]
    if exact:
        return exact
    prefix = lib_name + "."
    return [df for df in all_files if df.getName().startswith(prefix)]


def run():
    program = currentProgram
    ext_manager = program.getExternalManager()
    project_data = state.getProject().getProjectData()
    root_folder = project_data.getRootFolder()

    all_files = []
    collect_all_files(root_folder, all_files, set())

    lib_names = list(ext_manager.getExternalLibraryNames())

    resolved = []
    already = []
    ambiguous = []
    unresolved = []

    for lib_name in lib_names:
        if lib_name == UNKNOWN_LIBRARY_NAME:
            continue

        existing_path = ext_manager.getExternalLibraryPath(lib_name)
        if existing_path:
            already.append("{} -> {}".format(lib_name, existing_path))
            continue

        candidates = find_candidates(all_files, lib_name)
        if not candidates:
            unresolved.append(lib_name)
            continue

        chosen = sorted(candidates, key=lambda df: df.getName())[-1]
        ext_manager.setExternalPath(lib_name, chosen.getPathname(), False)
        resolved.append("{} -> {}".format(lib_name, chosen.getPathname()))
        if len(candidates) > 1:
            others = [c.getPathname() for c in candidates if c is not chosen]
            ambiguous.append("{}: chose {} over {}".format(lib_name, chosen.getPathname(), others))

    print("=== Newly resolved ({}) ===".format(len(resolved)))
    for line in resolved:
        print("  " + line)

    print("=== Already resolved ({}) ===".format(len(already)))
    for line in already:
        print("  " + line)

    if ambiguous:
        print("=== Ambiguous matches - verify these ({}) ===".format(len(ambiguous)))
        for line in ambiguous:
            print("  " + line)

    print("=== Still unresolved, no matching project file found ({}) ===".format(len(unresolved)))
    for line in unresolved:
        print("  " + line)


run()
