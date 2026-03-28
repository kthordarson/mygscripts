// AnalyzeOnly.java
// Headless-only: Auto-analyze every program in the project

import ghidra.app.script.GhidraScript;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.task.TaskMonitor;

public class AnalyzeOnly extends HeadlessScript {

    @Override
    protected void run() throws Exception {
        // Get the project
        Project project = getCurrentProject();
        if (project == null) {
            println("ERROR: No project open!");
            return;
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        processFolder(root);
        println("=== ANALYSIS COMPLETE ===");
    }

    private void processFolder(DomainFolder folder) throws Exception {
        // Process files
        for (DomainFile df : folder.getFiles()) {
            if (df.isProgram()) {
                analyzeProgram(df);
            }
        }
        // Recurse into subfolders
        for (DomainFolder sub : folder.getFolders()) {
            processFolder(sub);
        }
    }

    private void analyzeProgram(DomainFile df) throws Exception {
        String name = df.getName();
        println("Analyzing: " + name);

        // Open program (read-only)
        Program program = (Program) df.getReadOnlyDomainObject(
            this, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);

        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            mgr.initializeOptions();
            mgr.scheduleAllAnalyzers();
            mgr.waitForAnalysis(0, monitor);  // 0 = no timeout
            println("  → Done: " + name);
        } finally {
            program.release(this);
        }
    }
}