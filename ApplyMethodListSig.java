// Create TMethodPointer64/BufferHeader structs and apply method-list function signatures
// ApplyMethodListSig.java
// @author kth
// @category mygscripts

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ApplyMethodListSig extends GhidraScript {

    private ArrayDataType bytesN(int n) {
        // Use ByteDataType for portable padding across Ghidra versions
        return new ArrayDataType(ByteDataType.dataType, n, 1);
    }

    @Override
    public void run() throws Exception {

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CategoryPath cat = new CategoryPath("/Reversing");

        // ---- TMethodPointer64 { void* Code; void* Data; } ----
        StructureDataType tMethodPtrDT = new StructureDataType(cat, "TMethodPointer64", 0);
        tMethodPtrDT.add(PointerDataType.dataType, "Code", null);
        tMethodPtrDT.add(PointerDataType.dataType, "Data", null);
        tMethodPtrDT.setPackingEnabled(true);
        DataType tMethodPtr = dtm.addDataType(tMethodPtrDT, DataTypeConflictHandler.REPLACE_HANDLER);

        // ---- BufferHeader (packed, 16 bytes) ----
        StructureDataType bufHdrDT = new StructureDataType(cat, "BufferHeader", 0);
        bufHdrDT.add(bytesN(4), "reserved0", null);
        bufHdrDT.add(IntegerDataType.dataType, "flags", null);           // uint32 equivalent
        bufHdrDT.add(LongLongDataType.dataType, "capacity", null);       // uint64 equivalent
        bufHdrDT.setPackingEnabled(true);
        DataType bufHdr = dtm.addDataType(bufHdrDT, DataTypeConflictHandler.REPLACE_HANDLER);

        // ---- CRITICAL_SECTION placeholder (use real Windows type if imported) ----
        // If you have Windows types, replace with _RTL_CRITICAL_SECTION.
        StructureDataType critDT = new StructureDataType(cat, "CRITICAL_SECTION", 0);
        critDT.add(PointerDataType.dataType, "DebugInfo", null);
        critDT.add(IntegerDataType.dataType, "LockCount", null);
        critDT.add(IntegerDataType.dataType, "RecursionCount", null);
        critDT.add(PointerDataType.dataType, "OwningThread", null);
        critDT.add(PointerDataType.dataType, "LockSemaphore", null);
        critDT.add(LongLongDataType.dataType, "SpinCount", null);
        critDT.setPackingEnabled(true);
        DataType crit = dtm.addDataType(critDT, DataTypeConflictHandler.REPLACE_HANDLER);

        // ---- Temporary shell so we can reference MethodList in its own notify signature ----
        StructureDataType methodListShellDT = new StructureDataType(cat, "MethodList", 0);
        DataType methodListShell = dtm.addDataType(methodListShellDT, DataTypeConflictHandler.REPLACE_HANDLER);

        // notify: void (*notify)(MethodList*, MethodList*, const TMethodPointer64*, int)
        ParameterDefinition[] pdefs = new ParameterDefinition[] {
            new ParameterDefinitionImpl("self",  new PointerDataType(methodListShell), null),
            new ParameterDefinitionImpl("owner", new PointerDataType(methodListShell), null),
            new ParameterDefinitionImpl("entry", new PointerDataType(tMethodPtr), null),
            new ParameterDefinitionImpl("op",    IntegerDataType.dataType, null)
        };
        FunctionDefinitionDataType notifyDefDT = new FunctionDefinitionDataType(cat, "notify_fn");
        notifyDefDT.setReturnType(VoidDataType.dataType);
        notifyDefDT.setArguments(pdefs);
        notifyDefDT.setCallingConvention("__cdecl"); // x64 shows as __cdecl in Ghidra UI
        DataType notifyPtr = new PointerDataType(dtm.addDataType(notifyDefDT, DataTypeConflictHandler.REPLACE_HANDLER));

        // ---- Build the final MethodList layout ----
        StructureDataType methodListDT = new StructureDataType(cat, "MethodList", 0);
        methodListDT.add(notifyPtr, "notify", null);

        int offNotifyEnd = notifyPtr.getLength(); // typically 8
        int pad0 = Math.max(0, 0x18 - offNotifyEnd);
        methodListDT.add(bytesN(pad0), "_pad0", null);                     // up to offset 0x18

        methodListDT.add(new PointerDataType(tMethodPtr), "items", null);  // +0x18
        methodListDT.add(IntegerDataType.dataType, "length_and_flags", null); // +0x20

        int ptrLen = PointerDataType.dataType.getLength(); // 8 on x64
        int pad1 = Math.max(0, 0x40 - (0x18 + ptrLen + IntegerDataType.dataType.getLength()));
        methodListDT.add(bytesN(pad1), "_pad1", null);

        methodListDT.add(crit, "lock", null);                              // +0x40
        methodListDT.setPackingEnabled(true);

        // Replace the shell with the final definition, then load the managed type by path
        dtm.replaceDataType(methodListShell, methodListDT, true);
        DataType methodList = dtm.getDataType(new DataTypePath(cat, "MethodList"));

        // ---- Apply function signature to FUN_00912c70 ----
        Address funAddr = askAddress("Function address", "Enter address of FUN_00912c70");
        Function func = getFunctionAt(funAddr);
        if (func == null) func = createFunction(funAddr, "FUN_00912c70");

        // Signature: void FUN_00912c70(MethodList *self, const TMethodPointer64 *entry)
        FunctionDefinitionDataType fdefDT = new FunctionDefinitionDataType(cat, "FUN_00912c70_sig");
        fdefDT.setReturnType(VoidDataType.dataType);
        fdefDT.setCallingConvention("__cdecl");
        fdefDT.setArguments(new ParameterDefinition[] {
            new ParameterDefinitionImpl("self",  new PointerDataType(methodList), null),
            new ParameterDefinitionImpl("entry", new PointerDataType(tMethodPtr), null)
        });

        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(funAddr, fdefDT, SourceType.USER_DEFINED);
        if (!cmd.applyTo(currentProgram)) {
            printerr("Failed to apply signature at " + funAddr + " (check address and program)");
        } else {
            println("Applied signature and created types for FUN_00912c70 at " + funAddr);
        }
    }
}
