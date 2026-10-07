// Lists imported symbols and all internal functions that call their import thunks.
// @author kth
// @category mygscripts
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class ListImportCallers extends GhidraScript {
  public void run() throws Exception {
    FunctionManager fm = currentProgram.getFunctionManager();
    ReferenceManager rm = currentProgram.getReferenceManager();
    SymbolTable st = currentProgram.getSymbolTable();
    Map<String,Set<String>> out = new TreeMap<>();
    FunctionIterator fit = fm.getFunctions(true);
    while (fit.hasNext()) {
      Function f = fit.next();
      if (f.isExternal()) continue;
      InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
      while (ii.hasNext()) {
        Instruction ins = ii.next();
        for (Reference r : ins.getReferencesFrom()) {
          if (!r.getReferenceType().isCall()) continue;
          Address to = r.getToAddress();
          Function callee = fm.getFunctionAt(to);
          if (callee == null) continue;
          Function target = callee;
          if (callee.isThunk()) {
            Function tf = callee.getThunkedFunction(true);
            if (tf != null) target = tf;
          }
          if (!target.isExternal()) continue;
          String lib = target.getParentNamespace() == null ? "?" : target.getParentNamespace().getName();
          String key = lib + "!" + target.getName();
          out.computeIfAbsent(key,k->new TreeSet<>()).add(f.getName()+"@"+f.getEntryPoint());
        }
      }
    }
    for (Map.Entry<String,Set<String>> e : out.entrySet())
      println(e.getKey()+" <- "+String.join(", ",e.getValue()));
  }
}
