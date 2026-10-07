// Rename FUN_* callers of os_print_write using the tag string argument
// @author kth
// @category mygscripts
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class RenameOsPrintCallers extends GhidraScript {
	Long ev(Varnode v, int d) {
		if (v == null || d > 12)
			return null;
		if (v.isConstant() || v.isAddress())
			return v.getOffset();
		PcodeOp o = v.getDef();
		if (o == null)
			return null;
		try {
			switch (o.getOpcode()) {
				case PcodeOp.COPY:
				case PcodeOp.CAST:
					return ev(o.getInput(0), d + 1);
				case PcodeOp.PTRSUB:
				case PcodeOp.INT_ADD: {
					Long a = ev(o.getInput(0), d + 1), b = ev(o.getInput(1), d + 1);
					return a != null && b != null ? a + b : null;
				}
				case PcodeOp.PTRADD: {
					Long a = ev(o.getInput(0), d + 1), b = ev(o.getInput(1), d + 1), c = ev(o.getInput(2), d + 1);
					return a != null && b != null && c != null ? a + b * c : null;
				}
			}
		} catch (Exception e) {
		}
		return null;
	}

	String rs(Long p) {
		if (p == null)
			return null;
		try {
			Address a = toAddr(p);
			StringBuilder s = new StringBuilder();
			for (int i = 0; i < 128; i++) {
				int c = getByte(a.add(i)) & 255;
				if (c == 0)
					break;
				if (c < 32 || c > 126)
					return null;
				s.append((char) c);
			}
			return s.length() > 0 ? s.toString() : null;
		} catch (Exception e) {
			return null;
		}
	}

	public void run() throws Exception {
		// Address t = toAddr(0x404800L);
		Address t = toAddr(00439120L);
		Set<Function> fs = new LinkedHashSet<>();
		ReferenceIterator r = currentProgram.getReferenceManager().getReferencesTo(t);
		while (r.hasNext()) {
			Function f = getFunctionContaining(r.next().getFromAddress());
			if (f != null && f.getName().startsWith("FUN_"))
				fs.add(f);
		}
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		int n = 0, u = 0;
		for (Function f : fs) {
			String nm = null;
			HighFunction h = di.decompileFunction(f, 30, monitor).getHighFunction();
			if (h != null) {
				Iterator<PcodeOpAST> it = h.getPcodeOps();
				while (it.hasNext()) {
					PcodeOpAST o = it.next();
					if (o.getOpcode() == PcodeOp.CALL && o.getNumInputs() >= 6) {
						String q = rs(ev(o.getInput(5), 0));
						if (q != null && q.matches("[A-Za-z_][A-Za-z0-9_]*")) {
							nm = q;
							break;
						}
					}
				}
			}
			if (nm == null) {
				println("UNRESOLVED " + f.getName() + " @ " + f.getEntryPoint());
				u++;
				continue;
			}
			SymbolIterator si = currentProgram.getSymbolTable().getSymbols(nm);
			if (si.hasNext())
				nm = nm + "_" + f.getEntryPoint();
			String old = f.getName();
			f.setName(nm, SourceType.USER_DEFINED);
			println(old + " -> " + nm + " @ " + f.getEntryPoint());
			n++;
		}
		println("SUMMARY candidates=" + fs.size() + " renamed=" + n + " unresolved=" + u);
	}
}
