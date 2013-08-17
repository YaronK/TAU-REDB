from models import (Function, Description, String, Call,
                    Executable, Instruction, Graph, Block)


class FunctionWrapper:
    def __init__(self, attributes):
        for attr_name in attributes:
            setattr(self, attr_name, attributes[attr_name])

    def save(self):
        function, created = Function.objects.\
            get_or_create(signature=self.func_signature,
                          defaults={'args_size': self.args_size,
                                    'vars_size': self.vars_size,
                                    'regs_size': self.regs_size,
                                    'frame_size': self.frame_size,
                                    'num_of_strings': self.num_of_strings,
                                    'num_of_calls': self.num_of_calls,
                                    'num_of_insns': self.num_of_insns,
                                    'func_name': self.func_name,
                                    'exe_name': self.exe_name})

        # TODO: add "alternative_names" as a field.
        # TODO: un-comment
        """ if self.func_name not in function.names:
            function.names += self.func_name + ", "
        function.save()"""
        if not created:
            return function

        ExecutableWrapper(self.exe_signature, function, self.exe_name).save()

        graph = GraphWrapper(self.edges, self.blocks_bounds,
                             self.num_of_blocks, self.num_of_edges,
                             function).save()

        for block_id in range(len(self.blocks_bounds)):
            block = BlockWrapper(graph,
                                 self.dist_from_root[str(block_id)]).save()
            instructions = []
            start_offset = self.blocks_bounds[block_id][0]
            end_offset = self.blocks_bounds[block_id][1] + 1
            for offset in range(start_offset, end_offset):
                str_offset = str(offset)
                immediate = None
                if str_offset in self.immediates:
                    immediate = self.immediates[str_offset]
                string = None
                if str_offset in self.strings:
                    string = StringWrapper(self.strings[str_offset]).save()
                call = None
                if str_offset in self.calls:
                    call = \
                        CallWrapper(self.calls[str_offset]).save()
                instructions.\
                    append(InstructionWrapper(self.itypes[offset],
                                      offset, block,
                                      immediate,
                                      string,
                                      call).instruction)

            # SQLite limitation
            chunks = [instructions[x:x + 100]
                      for x in xrange(0, len(instructions), 100)]
            for chunk in chunks:
                Instruction.objects.bulk_create(chunk)

        return function


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
    def __init__(self, edges, blocks_bounds, num_of_blocks,
                 num_of_edges, function):
        self.edges = edges
        self.blocks_bounds = blocks_bounds
        self.num_of_blocks = num_of_blocks
        self.num_of_edges = num_of_edges
        self.function = function

    def save(self):
        return Graph.objects.create(edges=self.edges,
                                    blocks_bounds=self.blocks_bounds,
                                    num_of_blocks=self.num_of_blocks,
                                    num_of_edges=self.num_of_edges,
                                    function=self.function)


class BlockWrapper:
    def __init__(self, graph, dist_from_root):
        self.graph = graph
        self.dist_from_root = dist_from_root

    def save(self):
        return Block.objects.create(graph=self.graph,
                                    dist_from_root=self.dist_from_root)


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
