from models import (Function, Description, String, Call,
                    Executable, Instruction, Graph, Block)


class FunctionWrapper:
    def __init__(self, attributes):
        for attr_name in attributes:
            setattr(self, attr_name, attributes[attr_name])
        self.function = Function(signature=self.func_signature,
                                 args_size=self.args_size,
                                 vars_size=self.vars_size,
                                 regs_size=self.regs_size,
                                 frame_size=self.frame_size,
                                 num_of_strings=self.num_of_strings,
                                 num_of_calls=self.num_of_calls,
                                 num_of_insns=self.num_of_insns,
                                 func_name=self.func_name,
                                 exe_name=self.exe_name)
        self.executable_wrapper = ExecutableWrapper(self.exe_signature,
                                                    self.function,
                                                    self.exe_name)
        self.graph_wrapper = GraphWrapper(self.edges, self.blocks_bounds,
                                          self.num_of_blocks,
                                          self.num_of_edges,
                                          self.function)

    def save(self):
        try:
            Function.objects.get(signature=self.func_signature)
        except Function.DoesNotExist:
            self.function.save()

        self.executable_wrapper.save()

        self.graph_wrapper.save()

        return self.function


class StringWrapper:
    def __init__(self, value):
        self.value = value

    def save(self):
        obj = String.objects.get_or_create(value=self.value)
        return obj[0]


class CallWrapper:
    def __init__(self, name):
        self.name = name

    def save(self):
        obj = Call.objects.get_or_create(name=self.name)
        return obj[0]


class GraphWrapper:
    def __init__(self, immediates, strings, itypes, calls, blocks_bounds,
                 edges, function):

        num_of_blocks = len(blocks_bounds)
        num_of_edges = len(edges)
        self.graph = Graph(edges=edges, num_of_blocks=num_of_blocks,
                           num_of_edges=num_of_edges, function=function)
        distances = self.graph.get_distances()
        self.blocks_wrappers = []

        for block_id in num_of_blocks:
            bounds = blocks_bounds[block_id]
            if block_id in distances:  # reachable from root
                distance = distances[block_id]
            else:
                distance = -1
            self.blocks_wrappers.append(BlockWrapper(immediates, strings,
                                                    itypes, calls, bounds,
                                                    distance, self.graph))

    def save(self):
        self.graph.save()
        for block_wrapper in self.blocks_wrappers:
            block_wrapper.save()

        return self.graph


class BlockWrapper:
    def __init__(self, immediates, strings, itypes, calls, bounds, distance,
                 graph):
        self.block = Block(graph=graph, dist_from_root=distance)
        start_offset = bounds[0]
        end_offset = bounds[1] + 1

        self.instructions = []
        self.strings_wrappers = []
        self.calls_wrappers = []

        for offset in range(start_offset, end_offset):
            str_offset = str(offset)

            immediate = None
            if str_offset in immediates:
                immediate = immediates[str_offset]

            string = None
            if str_offset in strings:
                self.strings_wrappers.\
                append(StringWrapper(strings[str_offset]))

            call = None
            if str_offset in self.calls:
                self.calls_wrappers.append(CallWrapper(calls[str_offset]))

            self.instructions.append(InstructionWrapper(itypes[offset],
                                                        offset, self.block,
                                                        immediate, string,
                                                        call).instruction)

    def save(self):
        self.block.save()

        for string_wrapper in self.strings_wrappers:
            string_wrapper.save()

        for call_wrapper in self.calls_wrappers:
            call_wrapper.save()

        # SQLite limitation
        chunks = [self.instructions[x:x + 100]
                  for x in xrange(0, len(self.instructions), 100)]
        for chunk in chunks:
            Instruction.objects.bulk_create(chunk)

        return self.block


class ExecutableWrapper:
    def __init__(self, signature, function, exe_name):
        self.signature = signature
        self.function = function
        self.exe_name = exe_name

    def save(self):
        if not(self.signature == 'None'):
            exe, _ = Executable.objects.get_or_create(signature=self.signature)
            exe.functions.add(self.function)
            if self.exe_name not in exe.names:
                exe.names += self.exe_name + ", "
            exe.save()
            return exe


class InstructionWrapper:
    def __init__(self, itype, offset, block,
                 immediate=None, string=None, call=None):
        self.itype = itype
        self.offset = offset
        self.block = block
        self.immediate = immediate
        self.string = string
        self.call = call
        self.instruction = Instruction(block=self.block,
                                       itype=self.itype,
                                       offset=self.offset,
                                       immediate=self.immediate,
                                       string=self.string,
                                       call=self.call)


class DescriptionWrapper:
    def __init__(self, function_wrapper, description_data, user):
        self.function_wrapper = function_wrapper
        self.data = description_data
        self.user = user

    def save(self):
        func = self.function_wrapper.save()
        try:
            desc = func.description_set.get(data=self.data)
        except Description.DoesNotExist:
            try:
                desc = func.description_set.get(user=self.user)
                desc.data = self.data
                desc.save()
            except Description.DoesNotExist:
                desc = Description.objects.create(data=self.data,
                                                  function=func,
                                                  user=self.user)
        return desc
