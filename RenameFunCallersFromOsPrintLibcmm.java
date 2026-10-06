
// Rename FUN_* callers using os_print_write's source-function-name argument.
//@category ReverseEngineering
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class RenameFunCallersFromOsPrintLibcmm extends GhidraScript {
	private DecompInterface decomp;

	private Varnode strip(Varnode v, int n) {
		if (v == null || n > 12)
			return v;
		PcodeOp d = v.getDef();
		if (d == null)
			return v;
		int op = d.getOpcode();
		if (op == PcodeOp.COPY || op == PcodeOp.CAST || op == PcodeOp.INDIRECT)
			return strip(d.getInput(0), n + 1);
		if (op == PcodeOp.PTRSUB || op == PcodeOp.INT_ADD) {
			Varnode a = strip(d.getInput(0), n + 1), b = strip(d.getInput(1), n + 1);
			if (a != null && b != null && a.isConstant() && b.isConstant())
				return new Varnode(currentProgram.getAddressFactory().getDefaultAddressSpace()
						.getAddress(a.getOffset() + b.getOffset()), v.getSize());
		}
		return v;
	}

	private String str(Varnode v) {
		v = strip(v, 0);
		if (v == null || (!v.isAddress() && !v.isConstant()))
			return null;
		try {
			Address a = toAddr(v.getOffset());
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
		Address osEntry = toAddr("0014ddb0");
		Function os = getFunctionAt(osEntry);
		if (os == null) {
			println("ERROR no os_print_write at " + osEntry);
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
		for (Function f : callers) {
			monitor.checkCancelled();
			DecompileResults dr = decomp.decompileFunction(f, 30, monitor);
			HighFunction hf = dr.getHighFunction();
			String src = null;
			if (hf != null) {
				Iterator<PcodeOpAST> it = hf.getPcodeOps();
				while (it.hasNext()) {
					PcodeOpAST op = it.next();
					if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() <= 5
							|| op.getInput(0).getOffset() != osEntry.getOffset())
						continue;
					String c = clean(str(op.getInput(5)));
					if (c != null) {
						src = c;
						break;
					}
				}
			}
			if (src == null) {
				unresolved++;
				continue;
			}
			String wanted = src;
			for (Symbol s : currentProgram.getSymbolTable().getGlobalSymbols(wanted))
				if (!s.getAddress().equals(f.getEntryPoint())) {
					wanted = src + "__" + f.getEntryPoint();
					collisions++;
					break;
				}
			try {
				f.setName(wanted, SourceType.USER_DEFINED);
				renamed++;
				println("RENAMED " + f.getEntryPoint() + " " + wanted);
			} catch (Exception e) {
				println("FAILED " + f.getEntryPoint() + " " + e);
			}
		}
		println("SUMMARY callers_FUN=" + callers.size() + " renamed=" + renamed + " unresolved=" + unresolved
				+ " collisions=" + collisions);
		decomp.dispose();
	}
}
