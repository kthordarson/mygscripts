import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import java.util.*;

public class RenameWsockOrdinals extends GhidraScript {
    @Override
    public void run() throws Exception {
        Map<String, String> renames = new HashMap<>();
        renames.put("Ordinal_21", "setsockopt");
        renames.put("Ordinal_111", "WSAGetLastError");
        renames.put("Ordinal_12", "ioctlsocket");
        renames.put("Ordinal_20", "sendto");
        renames.put("Ordinal_9", "htons_ord9");
        renames.put("Ordinal_116", "WSACleanup");
        renames.put("Ordinal_115", "WSAStartup");

        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getSymbolIterator();
        int count = 0;
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!s.isExternal()) continue;
            String name = s.getName();
            if (renames.containsKey(name)) {
                String newName = renames.get(name);
                println("Renaming external symbol " + s.getName() + " @ " + s.getAddress() + " (namespace=" + s.getParentNamespace().getName() + ") -> " + newName);
                try {
                    s.setName(newName, SourceType.USER_DEFINED);
                    count++;
                } catch (Exception e) {
                    println("  FAILED: " + e.getMessage());
                }
            }
        }
        println("Renamed " + count + " external symbols.");
    }
}
