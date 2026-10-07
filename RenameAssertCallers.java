// Rename FUN_* callers of __assert_fail using the function-name string argument
// @author kth
// @category mygscripts
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.util.regex.*;

public class RenameAssertCallers extends GhidraScript {
    public void run() throws Exception {
        Function thunk = getFunctionAt(currentAddress.getAddressSpace().getAddress(0x14f570L));
        if (thunk == null) {
            println("thunk missing");
            return;
        }
        Set<Function> callers = new LinkedHashSet<>();
        ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(thunk.getEntryPoint());
        while (ri.hasNext()) {
            Reference r = ri.next();
            Function f = getFunctionContaining(r.getFromAddress());
            if (f != null && f.getName().startsWith("FUN_"))
                callers.add(f);
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Pattern p = Pattern.compile("__assert_fail\\s*\\([^;]*?,\\s*\"([^\"]+)\"\\s*\\)", Pattern.DOTALL);
        int renamed = 0, unresolved = 0, collisions = 0;
        for (Function f : callers) {
            DecompileResults dr = di.decompileFunction(f, 60, monitor);
            String c = dr.decompileCompleted() ? dr.getDecompiledFunction().getC() : "";
            Matcher m = p.matcher(c);
            String n = m.find() ? m.group(1) : null;
            if (n == null) {
                println("UNRESOLVED " + f.getName() + " @ " + f.getEntryPoint());
                unresolved++;
                continue;
            }
            n = n.replaceAll("[^A-Za-z0-9_.$]", "_");
            String old = f.getName();
            try {
                f.setName(n, SourceType.USER_DEFINED);
            } catch (Exception e) {
                n = n + "_" + f.getEntryPoint();
                f.setName(n, SourceType.USER_DEFINED);
                collisions++;
            }
            println(old + " @ " + f.getEntryPoint() + " -> " + n + " | " + f.getPrototypeString(false, false));
            renamed++;
        }
        di.dispose();
        println("SUMMARY callers_FUN=" + callers.size() + " renamed=" + renamed + " unresolved=" + unresolved
                + " collisions=" + collisions);
    }
}