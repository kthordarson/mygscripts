// Rename FUN_* callers using os_print_write's source-function-name argument.
// @author kth
// @category mygscripts

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class RenameFunCallersFromOsPrint extends GhidraScript {
    private DecompInterface decomp;

    private Varnode strip(Varnode v, int depth) {
        if (v == null || depth > 12)
            return v;
        PcodeOp d = v.getDef();
        if (d == null)
            return v;
        int op = d.getOpcode();
        if (op == PcodeOp.COPY || op == PcodeOp.CAST || op == PcodeOp.INDIRECT)
            return strip(d.getInput(0), depth + 1);
        if (op == PcodeOp.PTRSUB || op == PcodeOp.INT_ADD) {
            Varnode a = strip(d.getInput(0), depth + 1), b = strip(d.getInput(1), depth + 1);
            if (a != null && b != null && a.isConstant() && b.isConstant()) {
                AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
                return new Varnode(sp.getAddress(a.getOffset() + b.getOffset()), v.getSize());
            }
        }
        return v;
    }

    private String constantString(Varnode v) {
        v = strip(v, 0);
        if (v == null || (!v.isAddress() && !v.isConstant()))
            return null;
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v.getOffset());
            Data d = getDataAt(a);
            if (d != null && d.hasStringValue() && d.getValue() != null)
                return d.getValue().toString();
            StringBuilder s = new StringBuilder();
            for (int i = 0; i < 256; i++) {
                int b = getByte(a.add(i)) & 255;
                if (b == 0)
                    break;
                if (b < 32 || b > 126)
                    return null;
                s.append((char) b);
            }
            return s.length() == 0 ? null : s.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String clean(String s) {
        if (s == null)
            return null;
        s = s.trim();
        return s.matches("[A-Za-z_][A-Za-z0-9_:$~<>]*") ? s : null;
    }

    public void run() throws Exception {
        Address osEntry = toAddr("004054e0");
        Function os = getFunctionAt(osEntry);
        if (os == null) {
            println("ERROR: no function at " + osEntry);
            return;
        }
        Set<Function> callers = new LinkedHashSet<>();
        ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(osEntry);
        while (ri.hasNext()) {
            Function f = getFunctionContaining(ri.next().getFromAddress());
            if (f != null && f.getName().startsWith("FUN_"))
                callers.add(f);
        }
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        int renamed = 0, unresolved = 0, collisions = 0;
        List<String> out = new ArrayList<>();
        for (Function f : callers) {
            monitor.checkCancelled();
            HighFunction hf = decomp.decompileFunction(f, 30, monitor).getHighFunction();
            String src = null;
            if (hf != null) {
                Iterator<PcodeOpAST> it = hf.getPcodeOps();
                while (it.hasNext()) {
                    PcodeOpAST op = it.next();
                    if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() <= 5)
                        continue;
                    if (op.getInput(0).getOffset() != osEntry.getOffset())
                        continue;
                    String c = clean(constantString(op.getInput(5)));
                    if (c != null) {
                        src = c;
                        break;
                    }
                }
            }
            if (src == null) {
                unresolved++;
                out.add("UNRESOLVED " + f.getName() + " @ " + f.getEntryPoint());
                continue;
            }
            String old = f.getName(), wanted = src;
            List<Symbol> syms = currentProgram.getSymbolTable().getGlobalSymbols(wanted);
            boolean conflict = false;
            for (Symbol s : syms)
                if (!s.getAddress().equals(f.getEntryPoint()))
                    conflict = true;
            if (conflict) {
                wanted = src + "__" + f.getEntryPoint();
                collisions++;
            }
            try {
                f.setName(wanted, SourceType.USER_DEFINED);
                renamed++;
                out.add("RENAMED " + old + " @ " + f.getEntryPoint() + " -> " + wanted);
            } catch (Exception e) {
                out.add("FAILED " + old + " @ " + f.getEntryPoint() + " -> " + wanted + ": " + e);
            }
        }
        println(String.format("SUMMARY callers_FUN=%d renamed=%d unresolved=%d collisions=%d", callers.size(), renamed,
                unresolved, collisions));
        for (String x : out)
            println(x);
        decomp.dispose();
    }
}
