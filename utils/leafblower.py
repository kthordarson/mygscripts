from . import utils

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import BasicBlockModel


def get_argument_registers(current_program):
    """
    Get argument registers based on processor type.

    :param current_program: Ghidra program object.
    :type current_program: ghidra.program.model.listing.Program

    :returns: List of argument registers.
    :rtype: list(str)
    """
    arch = utils.get_processor(current_program)

    if arch == 'MIPS':
        return ['a0', 'a1', 'a2', 'a3']
    elif arch == 'ARM':
        return ['r0', 'r1', 'r2', 'r3']
    return []


class Function:
    CANDIDATES = {}

    def __init__(self, function, candidate_attr, has_loop=None,
                 argument_count=-1, format_arg_index=-1):

        self.name = str(function.getName())
        self.xref_count = function.getSymbol().getReferenceCount()
        self.has_loop = has_loop
        self.argument_count = argument_count
        self.format_arg_index = format_arg_index
        self.candidates = []
        if candidate_attr in self.CANDIDATES:
            self.candidates = self.CANDIDATES[candidate_attr]


class LeafFunction(Function):
    """
    Class to hold leaf function candidates.
    """

    CANDIDATES = {
        1: ['atoi', 'atol', 'strlen'],
        2: ['strcpy', 'strcat', 'strcmp', 'strstr', 'strchr', 'strrchr',
            'bzero'],
        3: ['strtol', 'strncpy', 'strncat', 'strncmp', 'memcpy', 'memmove',
            'bcopy', 'memcmp', 'memset']
    }

    def __init__(self, function, has_loop, argument_count):
        super().__init__(function, argument_count, has_loop, argument_count)

    def to_list(self):
        return [self.name, str(self.xref_count), str(self.argument_count),
                ','.join(self.candidates)]

    @classmethod
    def is_candidate(cls, function, has_loop, argument_count):
        """
        Determine is a function is a candidate for a leaf function. Leaf
        functions must have loops, make no external calls, require 1-3
        arguments, and have a reference count greater than 25.
        """
        if not has_loop:
            return False

        if argument_count > 3 or argument_count == 0:
            return False

        if function.getSymbol().getReferenceCount() < 25:
            return False

        return True


class FormatFunction(Function):
    """
    Class to hold format string function candidates.
    """

    CANDIDATES = {
        0: ['printf'],
        1: ['sprintf', 'fprintf', 'fscanf', 'sscanf'],
        2: ['snprintf']
    }

    def __init__(self, function, format_arg_index):
        super().__init__(function, format_arg_index,
                         format_arg_index=format_arg_index)

    def to_list(self):
        return [self.name, str(self.xref_count), str(self.format_arg_index),
                ','.join(self.candidates)]


class FinderBase:
    def __init__(self, program):
        self._program = program
        self._flat_api = FlatProgramAPI(program)
        self._monitor = self._flat_api.getMonitor()
        self._basic_blocks = BasicBlockModel(self._program)
        self._listing = self._program.getListing()

    def _display(self, title, entries):
        """
        Print a simple table to the terminal.

        :param title: Title of the table.
        :type title: list

        :param entries: Entries to print in the table.
        :type entries: list(list(str))
        """
        lines = [title] + entries

        # Find the largest entry in each column so it can be used later
        # for the format string.
        max_line_len = []
        for i in range(0, len(title)):
            column_lengths = [len(line[i]) for line in lines]
            max_line_len.append(max(column_lengths))

        # Account for largest entry, spaces, and '|' characters on each line.
        separator = '=' * (sum(max_line_len) + 3 * len(title) + 1)
        spacer = '|'

        def format_row(row):
            cells = ['{:<{width}}'.format(str(column), width=width)
                     for width, column in zip(max_line_len, row)]
            return spacer + ' ' + (' ' + spacer + ' ').join(cells) + ' ' + spacer

        # First block prints the title and '=' characters to make a title
        # border
        print(separator)
        print(format_row(title))
        print(separator)

        # Print the actual entries.
        for entry in entries:
            print(format_row(entry))
        print(separator)


class LeafFunctionFinder(FinderBase):
    """
    Leaf function finder class.
    """

    def __init__(self, program):
        super().__init__(program)
        self.leaf_functions = []

    def find_leaves(self):
        """
        Find leaf functions. Leaf functions are functions that have loops,
        make no external calls, require 1-3 arguments, and have a reference
        count greater than 25.
        """
        function_manager = self._program.getFunctionManager()

        for function in function_manager.getFunctions(True):
            if not self._function_makes_call(function):
                loops = self._function_has_loops(function)
                argc = self._get_argument_count(function)

                if LeafFunction.is_candidate(function, loops, argc):
                    self.leaf_functions.append(LeafFunction(function,
                                                            loops,
                                                            argc))

        self.leaf_functions.sort(key=lambda x: x.xref_count, reverse=True)

    def display(self):
        """
        Print leaf function candidates to the terminal.
        """
        title = ['Function', 'XRefs', 'Args', 'Potential Function']
        leaf_list = [leaf.to_list() for leaf in self.leaf_functions]

        self._display(title, leaf_list)

    def _function_makes_call(self, function):
        """
        Determine if a function makes external calls.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: True if the function makes external calls, False otherwise.
        :rtype: bool
        """
        for instruction in self._listing.getInstructions(function.getBody(),
                                                         True):
            if utils.is_call_instruction(instruction):
                return True
        return False

    def _function_has_loops(self, function):
        """
        Determine if a function has internal loops.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: True if the function has loops, False otherwise.
        :rtype: bool
        """

        function_blocks = self._basic_blocks.getCodeBlocksContaining(
            function.getBody(), self._monitor)

        while function_blocks.hasNext():
            block = function_blocks.next()
            destinations = block.getDestinations(self._monitor)

            # Determine if the current block can result in jumping to a block
            # above the end address and in the same function. This indicates
            # an internal loop.
            while destinations.hasNext():
                destination = destinations.next()
                dest_addr = destination.getDestinationAddress()
                destination_function = self._flat_api.getFunctionContaining(
                    dest_addr)
                if destination_function is not None and \
                        destination_function.equals(function) and \
                        dest_addr.compareTo(block.getMinAddress()) <= 0:
                    return True
        return False

    def _get_argument_count(self, function):
        """
        Determine the argument count to the function. This is determined by
        inspecting argument registers to see if they are read from prior to
        being written to.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: Argument count.
        :rtype: int
        """
        used_args = []
        arch_args = get_argument_registers(self._program)

        for curr_ins in self._listing.getInstructions(function.getBody(),
                                                      True):
            for op_index in range(0, curr_ins.getNumOperands()):
                ref_type = curr_ins.getOperandRefType(op_index)
                # We only care about looking at reads and writes. Reads that
                # include and index into a register show as 'data' so look
                # for those as well.
                if ref_type not in [RefType.WRITE, RefType.READ, RefType.DATA]:
                    continue

                # Check to see if the argument is an argument register. Remove
                # that register from the arch_args list so it can be ignored
                # from now on. If reading from the register add it to the
                # used_args list so we know its a used parameter.
                operands = curr_ins.getOpObjects(op_index)
                for operand in operands:
                    op_string = str(operand.toString())
                    if op_string in arch_args:
                        arch_args.remove(op_string)
                        if ref_type in [RefType.READ, RefType.DATA]:
                            used_args.append(op_string)

        return len(used_args)


class FormatStringFunctionFinder(FinderBase):
    def __init__(self, program):
        super().__init__(program)
        self._memory_map = self._program.getMemory()
        self.format_strings = self._find_format_strings()
        self.format_functions = []

    def _find_format_strings(self):
        """
        Find strings that contain format parameters.

        :returns: List of addresses that represent format string parameters.
        :rtype: list(ghidra.program.model.listing.Address
        """
        format_strings = []
        memory = self._memory_map.getAllInitializedAddressSet()
        strings = self._flat_api.findStrings(memory, 2, 1, True, True)

        for string in strings:
            curr_string = str(string.getString(self._memory_map))
            if '%' in curr_string:
                format_strings.append(string.getAddress())
        return format_strings

    def _find_function_by_instruction(self, instruction):
        """
        Find function associated with the instruction provided. Used to find
        function calls associated with parameters. Only searches in the
        code block of the provided instruction.

        :param instruction: Instruction to begin search from.
        :type instruction: ghidra.program.model.listing.Instruction

        :returns: Function if found, None otherwise.
        :rtype: ghidra.program.model.listing.Function
        """
        containing_blocks = self._basic_blocks.getCodeBlocksContaining(
            instruction.getAddress(), self._monitor)
        if not containing_blocks:
            return None
        block_max = containing_blocks[0].getMaxAddress()

        # Check if the current instruction is in the delay slot, back up one
        # instruction if true in case its a call.
        if instruction.isInDelaySlot():
            curr_ins = instruction.getPrevious()
        else:
            curr_ins = instruction

        while curr_ins and curr_ins.getAddress().compareTo(block_max) < 0:
            if utils.is_call_instruction(curr_ins):
                function_flow = curr_ins.getFlows()
                if function_flow is not None and len(function_flow) > 0:
                    # The call instruction should only have one flow so
                    # grabbing the first flow is fine.
                    return self._flat_api.getFunctionAt(function_flow[0])
            curr_ins = curr_ins.getNext()

        return None

    def display(self):
        """
        Print format function candidates to the terminal.
        """
        title = ['Function', 'XRefs', 'Fmt Index', 'Potential Function']
        format_list = [fmt_fn.to_list() for fmt_fn in self.format_functions]

        self._display(title, format_list)

    def find_functions(self):
        """
        Find functions that take format strings as an argument.
        """
        processed_functions = []
        registers = get_argument_registers(self._program)

        for string in self.format_strings:
            references = self._flat_api.getReferencesTo(string)
            for reference in references:
                if reference.getReferenceType() != RefType.PARAM:
                    continue

                # Get the instruction that references the format string.
                instruction = self._flat_api.getInstructionAt(
                    reference.getFromAddress())
                if instruction is None:
                    continue

                function = self._find_function_by_instruction(instruction)
                if not function:
                    continue

                function_name = str(function.getName())

                if function_name in processed_functions:
                    continue

                register_used = instruction.getOpObjects(
                    reference.getOperandIndex())
                if not register_used:
                    continue
                try:
                    register_index = registers.index(
                        str(register_used[0].toString()))
                except ValueError:
                    continue

                self.format_functions.append(FormatFunction(function,
                                                            register_index))

                processed_functions.append(function_name)

        # Sort the functions by cross reference count
        self.format_functions.sort(key=lambda fmt_fn: fmt_fn.xref_count,
                                   reverse=True)
