// Rename generic thunks to KERNEL32.DLL imports as call_<import>
// @author kth
// @category mygscripts
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.util.*;

public class RenameKernel32Thunks extends GhidraScript {
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator fit = fm.getFunctions(true);
        List<String> renamed = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();
        while (fit.hasNext()) {
            Function f = fit.next();
            if (f.isExternal()) continue;
            String name = f.getName();
            boolean generic = name.startsWith("ghidra_guess_") || name.startsWith("FUN_");
            if (!generic) continue;
            if (!f.isThunk()) continue;
            Function target = f.getThunkedFunction(true);
            if (target == null || !target.isExternal()) continue;
            Namespace ns = target.getParentNamespace();
            if (ns == null || !ns.getName().equals("KERNEL32.DLL")) continue;
            String newName = "call_" + target.getName();
            String candidate = newName;
            int suffix = 1;
            while (!st.getGlobalSymbols(candidate).isEmpty()) {
                candidate = newName + "_" + suffix;
                suffix++;
            }
            try {
                f.setName(candidate, SourceType.USER_DEFINED);
                renamed.add(name + " @ " + f.getEntryPoint() + " -> " + candidate);
            } catch (Exception e) {
                println("FAILED renaming " + name + ": " + e.getMessage());
            }
        }
        println("Renamed " + renamed.size() + " thunks:");
        for (String r : renamed) println("  " + r);
    }
}
