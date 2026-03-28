#@author kth
#@category mygscripts
#@description Script requests current variable name and desired new name. It then iterates through all functions, renaming local variables and parameters. Note: Script does not verify that no other variable/parameter within the function is already using the new name.
#@menupath CustomerSubmission.Search.Rename Variable or Parameter (Python)

from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import InvalidInputException, DuplicateNameException

# Get current variable/parameter name from user input
curName = askString("Current variable/parameter name", "Current Name")

if curName is None:
    print("Operation cancelled: No current name provided.")
else:
    # Get desired new variable/parameter name from user input
    newName = askString("New variable/parameter name", "New Name")

    if newName is None:
        print("Operation cancelled: No new name provided.")
    else:
        renamed_count = 0  # Counter for successfully renamed items

        # Start a transaction so changes can be undone
        transactionID = currentProgram().startTransaction("Rename Variables/Parameters Script")
        commit_changes = False  # Flag to control if changes should be committed

        try:
            functionManager = currentProgram().getFunctionManager()
            functions = functionManager.getFunctions(True)  # Iterate forward

            for func in functions:
                if monitor().isCancelled():
                    print("Operation cancelled by user via monitor().")
                    break

                # Process local variables
                local_variables = func.getLocalVariables()
                for var in local_variables:
                    if var.getName() == curName:
                        print("In function '{}', found local variable '{}'. Attempting to rename to '{}'.".format(
                            func.getName(), var.getName(), newName))
                        try:
                            var.setName(newName, SourceType.USER_DEFINED)
                            renamed_count += 1
                        except DuplicateNameException as e:
                            print("  WARNING: Could not rename local variable '{}' in function '{}' to '{}'. Name already exists: {}".format(
                                curName, func.getName(), newName, e.getMessage()))
                        except InvalidInputException as e:
                            print("  ERROR: Could not rename local variable '{}' in function '{}' to '{}'. Invalid name: {}".format(
                                curName, func.getName(), newName, e.getMessage()))
                        except Exception as e:
                            print("  ERROR: An unexpected error occurred while renaming local variable '{}' in function '{}': {}".format(
                                curName, func.getName(), e))

                # Process parameters
                parameters = func.getParameters()
                for param in parameters:
                    if param.getName() == curName:
                        print("In function '{}', found parameter '{}'. Attempting to rename to '{}'.".format(
                            func.getName(), param.getName(), newName))
                        try:
                            param.setName(newName, SourceType.USER_DEFINED)
                            renamed_count += 1
                        except DuplicateNameException as e:
                            print("  WARNING: Could not rename parameter '{}' in function '{}' to '{}'. Name already exists: {}".format(
                                curName, func.getName(), newName, e.getMessage()))
                        except InvalidInputException as e:
                            print("  ERROR: Could not rename parameter '{}' in function '{}' to '{}'. Invalid name: {}".format(
                                curName, func.getName(), newName, e.getMessage()))
                        except Exception as e:
                            print("  ERROR: An unexpected error occurred while renaming parameter '{}' in function '{}': {}".format(
                                curName, func.getName(), e))


            if not monitor().isCancelled():
                commit_changes = True

        finally:
            currentProgram().endTransaction(transactionID, commit_changes)

        if not monitor().isCancelled():
            print("Found and renamed {} instances of '{}' to '{}'.".format(renamed_count, curName, newName))
        else:
            print("Operation was cancelled. {} instances of '{}' were renamed to '{}' before cancellation.".format(
                renamed_count, curName, newName))

