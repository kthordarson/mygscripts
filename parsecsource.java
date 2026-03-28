// ParseCScript.java
import ghidra.app.script.GhidraScript;
import java.io.*;
import java.util.regex.*;

public class ParseCScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Prompt user for the C source file path
        String sourcePath = askFile("Select C Source File", "Choose").getAbsolutePath();
        println("Parsing C source file: " + sourcePath);

        // Read the source file
        StringBuilder sourceCode = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(sourcePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sourceCode.append(line).append("\n");
            }
        } catch (IOException e) {
            println("Error reading file: " + e.getMessage());
            return;
        }

        // Regular expression to match function declarations
        // Matches: "return_type function_name(param_type param_name, ...)"
        String funcPattern = "\\b(\\w+\\s*\\**)\\s+(\\w+)\\s*\\(([^)]*)\\)\\s*\\{?";
        Pattern pattern = Pattern.compile(funcPattern);
        Matcher matcher = pattern.matcher(sourceCode.toString());

        // Parse and print function declarations
        println("Found functions:");
        while (matcher.find()) {
            String returnType = matcher.group(1).trim();
            String funcName = matcher.group(2).trim();
            String params = matcher.group(3).trim();

            // Split parameters and clean up
            String[] paramList = params.isEmpty() ? new String[0] : params.split(",");
            StringBuilder paramStr = new StringBuilder();
            for (String param : paramList) {
                param = param.trim();
                if (!param.isEmpty()) {
                    paramStr.append(param).append(", ");
                }
            }
            if (paramStr.length() > 0) {
                paramStr.setLength(paramStr.length() - 2); // Remove trailing comma
            }

            println(String.format("Function: %s %s(%s)", returnType, funcName, paramStr.toString()));
        }

        // Optional: Add to Ghidra program (e.g., create symbols or comments)
        // Example: Add a comment in the current program
        if (currentProgram != null) {
            currentProgram.getListing().setComment(currentAddress, 0, "Parsed C source: " + sourcePath);
            println("Added comment to program at " + currentAddress);
        }
    }
}