# @author kth
# @category mygscripts
# GptHidra with GitHub Copilot CLI support
# Author: Modified for Kristjan Thordarson

import os
import tempfile
import subprocess
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

# === Configuration ===
USE_COPILOT_CLI = True  # Set to False to use OpenAI API fallback
OPENAI_API_KEY = ''     # Fill in your OpenAI API key if using fallback

def get_decompiled_code(function):
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    result = decompiler.decompileFunction(function, 60, ConsoleTaskMonitor())
    return result.getDecompiledFunction().getC()

def explain_with_copilot_cli(code):
    try:
        process = subprocess.Popen(
            ["gh", "copilot", "explain"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(input=code.encode("utf-8"))
        if stderr:
            return "Copilot CLI error:\n" + stderr
        return stdout
    except Exception as e:
        return "Error running Copilot CLI: " + str(e) + "\n" + str(type(e))


def oldv2explain_with_copilot_cli(code):

    with tempfile.NamedTemporaryFile(delete=False, suffix=".c", mode='w') as temp_file:
        temp_file.write(code)
        temp_file_path = temp_file.name
    print("Temporary file created at: ", temp_file_path)
    try:
        process = subprocess.Popen(["C:/Users/KT90/AppData/Local/GitHub CLI/extensions/gh-copilot/gh-copilot.exe", "explain", temp_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stderr:
            return "Copilot CLI error:\n" + str(stderr)
        return stdout
    except Exception as e:
        return "Error running Copilot CLI: " + str(e) + "\n" + str(type(e))
    finally:
        os.remove(temp_file_path)


def old_explain_with_copilot_cli(code):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c", mode='w') as temp_file:
        temp_file.write(code)
        temp_file_path = temp_file.name

    try:
        result = subprocess.run(["copilot", "explain", temp_file_path], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return "Error running Copilot CLI: " + str(e)
    finally:
        os.remove(temp_file_path)


# === Main Execution ===
function = getFunctionContaining(currentAddress)
if function is None:
    print("No function found at current address.")
else:
    code = get_decompiled_code(function)
    print("Decompiled Function Length: ", len(code))

    explanation = explain_with_copilot_cli(code)

    print("\nAI Explanation:\n", explanation)
