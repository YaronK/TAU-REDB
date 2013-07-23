from models import Function, Description, String, LibraryCall, Executable, \
    Instruction, Graph


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
                                    'num_of_lib_calls': self.num_of_lib_calls,
                                    'num_of_insns': self.num_of_insns})

        if not created:
            return function
        ExecutableWrapper(self.exe_signature, function).save()
        GraphWrapper(self.edges, self.blocks_data, self.num_of_blocks,
                     self.num_of_edges, function).save()

        instructions = []
        for offset in range(len(self.itypes)):
            str_offset = str(offset)
            immediate = None
            if str_offset in self.immediates:
                immediate = self.immediates[str_offset]
            string = None
            if str_offset in self.strings:
                string = StringWrapper(self.strings[str_offset]).save()
            lib_call = None
            if str_offset in self.library_calls:
                lib_call = \
                    LibraryCallWrapper(self.library_calls[str_offset]).save()
            instructions.\
                append(InstructionWrapper(self.itypes[offset],
                                          offset, function,
                                          immediate,
                                          string,
                                          lib_call).instruction)

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


class LibraryCallWrapper:
    def __init__(self, name):
        self.name = name

    def save(self):
        obj = LibraryCall.objects.get_or_create(name=self.name)
        return obj[0]


class GraphWrapper:
    def __init__(self, edges, blocks_data, num_of_blocks, num_of_edges,
                 function):
        self.edges = edges
        self.blocks_data = blocks_data
        self.num_of_blocks = num_of_blocks
        self.num_of_edges = num_of_edges
        self.function = function

    def save(self):
        return Graph.objects.create(edges=self.edges,
                                    blocks_data=self.blocks_data,
                                    num_of_blocks=self.num_of_blocks,
                                    num_of_edges=self.num_of_edges,
                                    function=self.function)


class ExecutableWrapper:
    def __init__(self, signature, function):
        self.signature = signature
        self.function = function

    def save(self):
        if not(self.signature == 'None'):
            obj = Executable.objects.get_or_create(signature=self.signature)
            obj[0].functions.add(self.function)
            return obj[0]


class InstructionWrapper:
    def __init__(self, itype, offset, function,
                 immediate=None, string=None, lib_call=None):
        self.itype = itype
        self.offset = offset
        self.function = function
        self.immediate = immediate
        self.string = string
        self.lib_call = lib_call
        self.instruction = Instruction(function=self.function,
                                       itype=self.itype,
                                       offset=self.offset,
                                       immediate=self.immediate,
                                       string=self.string,
                                       lib_call=self.lib_call)


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
