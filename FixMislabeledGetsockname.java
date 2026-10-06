import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class FixMislabeledGetsockname extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getSymbolIterator();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!s.isExternal()) continue;
            if (s.getName().equals("gethostbyname") && s.getParentNamespace().getName().equals("WSOCK32.DLL")) {
                println("Found: " + s.getName() + " @ " + s.getAddress());
                s.setName("getsockname", SourceType.USER_DEFINED);
                println("Renamed to 'getsockname'");

                Address thunkAddr = currentProgram.getAddressFactory().getAddress("00457e08");
                Listing listing = currentProgram.getListing();
                String note = "NOTE (verified 2026): Originally auto-named 'gethostbyname' by Ghidra's PE import " +
                    "parser, but the sole caller (bind_socket_0 @ 0043bb0e) pushes THREE args -- a SOCKET handle " +
                    "(closest to call), a pointer (ESP+4), and a second pointer (ESP+0x14) -- whereas real " +
                    "gethostbyname(const char*) takes exactly one string-pointer arg. The shape (SOCKET, sockaddr*, " +
                    "int*) plus the fact the caller immediately memcpy's bytes out of the same stack buffer right " +
                    "after the call (extracting address bytes, not dereferencing a returned hostent*) matches " +
                    "getsockname(SOCKET s, struct sockaddr *name, int *namelen) exactly -- the standard call to " +
                    "recover the locally bound address/port after bind(). Renamed accordingly. This is the second " +
                    "mislabeled entry found in this WSOCK32.DLL import block (see also the 'ntohl'->socket fix at " +
                    "00457e1a) -- worth spot-checking the remaining WSOCK32 imports for the same class of error.";
                listing.setComment(thunkAddr, CodeUnit.PLATE_COMMENT, note);
                println("Added plate comment at " + thunkAddr);
            }
        }
    }
}
