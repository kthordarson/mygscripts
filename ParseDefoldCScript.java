// ParseDefoldCScript.java
import ghidra.app.script.GhidraScript;
import java.io.*;
import java.util.regex.*;

public class ParseDefoldCScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Prompt for the C source or header file
        String sourcePath = askFile("Select C Source/Header File", "Choose").getAbsolutePath();
        println("Parsing file: " + sourcePath);

        // Read the source file
        StringBuilder sourceCode = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(sourcePath))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                sourceCode.append(line).append("\n");
                // Check for #error directives
                if (line.matches("^\\s*#error\\s+.*")) {
                    println("WARNING: #error directive at line " + lineNumber + ": " + line);
                }
                // Check for C++ namespace
                if (line.matches("^\\s*namespace\\s+\\w+\\s*\\{.*$")) {
                    println("WARNING: C++ namespace detected at line " + lineNumber + ": " + line);
                }
                // Check for trailing commas or stray braces
                if (line.matches(".*,\\s*}\\s*$")) {
                    println("WARNING: Potential trailing comma at line " + lineNumber + ": " + line);
                }
                if (line.matches("^\\s*}\\s*$")) {
                    println("WARNING: Stray closing brace at line " + lineNumber + ": " + line);
                }
            }
        } catch (IOException e) {
            println("Error reading file: " + e.getMessage());
            return;
        }

        // Preprocessor simulation: Define macros
        String[] macros = {
            "__linux__=1",
            "DM_PLATFORM_LINUX=1",
            "__GNUC__=8",
            "__BYTE_ORDER=__LITTLE_ENDIAN",
            "_XOPEN_SOURCE=700",
            "__cplusplus=" // Undefine C++ macro
        };
        for (String macro : macros) {
            sourceCode.insert(0, "#define " + macro + "\n");
        }

        // Parse #include directives
        Pattern includePattern = Pattern.compile("#include\\s+[<\"]([^>\"]+)[>\"]");
        Matcher includeMatcher = includePattern.matcher(sourceCode.toString());
        while (includeMatcher.find()) {
            String includeFile = includeMatcher.group(1);
            println("Found include: " + includeFile);
            String[] includePaths = {
                "/usr/include",
                "/home/kth/temp/randomgits/defold/engine/dlib/src",
                "/home/kth/temp/randomgits/defold/engine/dlib/include",
                "/home/kth/temp/randomgits/defold/engine/dmsdk",
                "/home/kth/temp/randomgits/defold/build/dmsdk",
                "/home/kth/temp/stubs"
            };
            boolean found = false;
            for (String path : includePaths) {
                File file = new File(path + "/" + includeFile);
                if (file.exists()) {
                    found = true;
                    println("Resolved include: " + file.getAbsolutePath());
                    break;
                }
            }
            if (!found) {
                println("WARNING: Unresolved include: " + includeFile);
            }
        }

        // Parse function declarations
        String funcPattern = "\\b(\\w+\\s*\\**)\\s+(\\w+)\\s*\\(([^)]*)\\)\\s*\\{?";
        Pattern pattern = Pattern.compile(funcPattern);
        Matcher matcher = pattern.matcher(sourceCode.toString());

        println("Found functions:");
        while (matcher.find()) {
            String returnType = matcher.group(1).trim();
            String funcName = matcher.group(2).trim();
            String params = matcher.group(3).trim();

            StringBuilder paramStr = new StringBuilder();
            String[] paramList = params.isEmpty() ? new String[0] : params.split(",");
            for (String param : paramList) {
                param = param.trim();
                if (!param.isEmpty()) {
                    paramStr.append(param).append(", ");
                }
            }
            if (paramStr.length() > 0) {
                paramStr.setLength(paramStr.length() - 2);
            }

            println(String.format("Function: %s %s(%s)", returnType, funcName, paramStr.toString()));
        }

        // Add comment to program
        if (currentProgram != null) {
            currentProgram.getListing().setComment(currentAddress, 0, "Parsed Defold source: " + sourcePath);
            println("Added comment to program at " + currentAddress);
        }
    }
}