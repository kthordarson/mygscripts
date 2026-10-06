
// Recover source-level function names embedded in os_print_write/__assert_fail calls.
//@category ReverseEngineering
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

public class RenameFunFromDiagnostics extends GhidraScript {
    private String readCString(long off) {
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
            StringBuilder s = new StringBuilder();
            for (int i = 0; i < 256; i++) {
                byte b = currentProgram.getMemory().getByte(a.add(i));
                if (b == 0)
                    break;
                int c = b & 0xff;
                if (c < 0x20 || c > 0x7e)
                    return null;
                s.append((char) c);
            }
            return s.length() == 0 ? null : s.toString();
        }
        catch (Exception e) {
            return null;
        }
    }

    private String clean(String s) {
        if (s == null || !s.matches("[A-Za-z_][A-Za-z0-9_:~]*"))
            return null;
        return s.replace("::", "_").replace("~", "dtor_");
    }

    private String uniqueName(String base, Function f) {
        Function x = getFunction(base);
        if (x == null || x.equals(f))
            return base;
        return base + "_" + f.getEntryPoint().toString().replace("0x", "");
    }

    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        int scanned = 0, osHits = 0, assertHits = 0, renamed = 0, unresolved = 0;
        List<Function> funcs = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.getName().startsWith("FUN_"))
                funcs.add(f);
        }
        for (Function f : funcs) {
            if (monitor.isCancelled())
                break;
            scanned++;
            DecompileResults dr = di.decompileFunction(f, 30, monitor);
            HighFunction hf = dr.getHighFunction();
            if (hf == null)
                continue;
            String recovered = null;
            Iterator<PcodeOpAST> ops = hf.getPcodeOps();
            while (ops.hasNext() && recovered == null) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() < 2)
                    continue;
                Varnode tv = op.getInput(0);
                if (!tv.isAddress() && !tv.isConstant())
                    continue;
                Address ta = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(tv.getOffset());
                Function callee = currentProgram.getFunctionManager().getFunctionAt(ta);
                if (callee == null)
                    continue;
                String cn = callee.getName();
                int arg = -1;
                if (cn.contains("os_print_write")) {
                    arg = 5;
                    osHits++;
                }
                else if (cn.contains("__assert_fail")) {
                    arg = 4;
                    assertHits++;
                }
                else
                    continue;
                if (op.getNumInputs() <= arg)
                    continue;
                Varnode av = op.getInput(arg);
                if (!av.isConstant() && !av.isAddress())
                    continue;
                recovered = clean(readCString(av.getOffset()));
            }
            if (recovered != null) {
                String nn = uniqueName(recovered, f);
                try {
                    f.setName(nn, SourceType.USER_DEFINED);
                    renamed++;
                    println(f.getEntryPoint() + " " + nn);
                }
                catch (Exception e) {
                    unresolved++;
                    println("FAILED " + f.getEntryPoint() + " " + recovered + ": " + e);
                }
            }
            else {
                // Count only diagnostic callers that could not yield a source name is intentionally omitted here.
            }
        }
        println("SUMMARY scanned_FUN=" + scanned + " os_calls_seen=" + osHits +
            " assert_calls_seen=" + assertHits + " renamed=" + renamed + " failures=" + unresolved);
        di.dispose();
    }
}
