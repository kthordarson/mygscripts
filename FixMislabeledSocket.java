import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FixMislabeledSocket extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getSymbolIterator();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!s.isExternal()) continue;
            if (s.getName().equals("ntohl") && s.getParentNamespace().getName().equals("WSOCK32.DLL")) {
                println("Found: " + s.getName() + " @ " + s.getAddress());
                s.setName("socket", SourceType.USER_DEFINED);
                println("Renamed to 'socket'");

                // add a plate comment on the code-space thunk (0x00457e1a) documenting the finding
                Address thunkAddr = currentProgram.getAddressFactory().getAddress("00457e1a");
                Listing listing = currentProgram.getListing();
                String note = "NOTE (verified 2026): This slot was originally auto-named 'ntohl' by Ghidra's PE " +
                    "import parser, but the only caller (bind_socket_0 @ 0043bb0e) pushes THREE stack dwords " +
                    "(0x6, 0x2, 0x3e8) before this call, whereas real ntohl(u_long) takes one stdcall param. " +
                    "A genuine 1-param stdcall ntohl would leave the stack unbalanced by 8 bytes and corrupt " +
                    "the caller's register-restore epilogue (ADD ESP,0x18 + 6 POPs) -- which the shipped binary " +
                    "clearly does not suffer from. Renamed to socket(int af, int type, int protocol) as the best-fit " +
                    "3-int-arg Winsock 1.1 call used in a classic socket-setup sequence (result checked against " +
                    "INVALID_SOCKET and stored in the persistent handle later passed to bind/closesocket/ioctlsocket). " +
                    "CAVEAT: exact arg->parameter mapping (af/type/protocol vs a non-cdecl push order used elsewhere " +
                    "in this binary) is not 100% certain -- af=6 doesn't match textbook AF_INET=2, so verify against " +
                    "known network behavior if possible.";
                listing.setComment(thunkAddr, CodeUnit.PLATE_COMMENT, note);
                println("Added plate comment at " + thunkAddr);
            }
        }
    }
}
