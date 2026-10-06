
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd;
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd.OffsetPcodeOpPair;
import ghidra.app.script.*;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import docking.options.OptionsService;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.*;
import ghidra.app.tablechooser.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
public class CreateStructure extends GhidraScript {

	@Override
	public void run() throws Exception {
		/*println("" + currentLocation.toString());
		FillOutStructureCmd fillCmd =
				new FillOutStructureCmd(currentProgram, currentLocation, state.getTool());
		fillCmd.applyTo(currentProgram, this.monitor);*/
		FunctionIterator funcs = currentProgram().getFunctionManager().getFunctions(true);
		DecompInterface decomp = setUpDecompiler(currentProgram);
		for (Function fn : funcs) {
			Variable[] allvars = fn.getAllVariables();
			for(Variable var : allvars) {
				/*DecompileResults res = decomp.decompileFunction(fn, 10000, monitor);
				ClangNode nodres = null;
				ClangTokenGroup ccode = res.getCCodeMarkup();
				println("Decompiled " + fn.getName());
				ClangToken tokeres = new ClangToken((ClangNode) var.getVariableStorage().getFirstVarnode());
				*/
				DataType dattyp = var.getDataType();
				String datatypstring = dattyp.getDisplayName();
				if(!datatypstring.contains("*")) continue;
				datatypstring = datatypstring.replaceAll("\\[|\\]|\\*|\\s", "");
		        //println(datatypstring = datatypstring.replaceAll("\\[|\\]|\\*|\\s", ""));
		        DecompileResults res = decomp.decompileFunction(fn, 10000, monitor);
		        
		        //println("type : " + dattyp.getCategoryPath().getName());
		        
		        if(!dattyp.getCategoryPath().getName().equals("Demangler")) {
		        	continue;
		        }
		        
		        ClangTokenGroup tokengrp = res.getCCodeMarkup();
		        
		        if(tokengrp == null) continue;
		        
		        ClangToken tokeres = null;
		        
		        //println("searching for " + datatypstring);
		        
		        mainloop:
		        for(ClangNode  token : tokengrp) {
		        	if(token instanceof ClangFuncProto) {
		        		for(ClangNode  outter : ((ClangFuncProto)token)) {
		        			if(outter instanceof ClangVariableDecl)
		        			for(ClangNode inner2 : ((ClangVariableDecl)outter)) {
			        			if(inner2 instanceof ClangToken) {
			        				if(((ClangToken)inner2).getText().equals(datatypstring)) {
						        		tokeres = (ClangToken)inner2;
						        		//println(inner2.getClass().toString());
						        		break mainloop;
						        	}
				        			else {
				        				//println("" + ((ClangToken)inner2).getText());
				        			}
			        			}
			        			else {
			        				//println(inner2.getClass().toString());
			        			}
		        			}
		        	}
		        }
		        }
		        if(tokeres == null) continue;
		        //println("found");
		        
				//ClangToken tokeres = new ClangToken(null, datatypstring);
				DecompilerLocation loc = new DecompilerLocation(currentProgram, fn.getEntryPoint(), fn.getEntryPoint(), res, tokeres,1,1);
				println("" + loc);
				FillOutStructureCmd fillCmd =
						new FillOutStructureCmd(currentProgram, loc, state.getTool());
				fillCmd.applyTo(currentProgram, this.monitor);
			}
		}
	}
	
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(currentProgram)) {
			println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}
}