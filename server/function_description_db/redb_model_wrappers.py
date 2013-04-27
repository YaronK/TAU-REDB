from models import (Function, Description, String, LibraryCall,
                    Executable, Instruction, User, Graph)


class FunctionWrapper:
    def __init__(self, attributes):
        print "->FunctionWrapper.__init__"
        for attr_name in attributes:
            setattr(self, attr_name, attributes[attr_name])
        print "FunctionWrapper.__init__->"

    def save(self):
        print "->FunctionWrapper.save"
        function, created = Function.objects.\
            get_or_create(signature=self.func_signature,
                          defaults={'args_size': self.args_size,
                                    'vars_size': self.vars_size,
                                    'regs_size': self.regs_size,
                                    'frame_size': self.frame_size,
                                    'num_of_strings': self.num_of_strings,
                                    'num_of_lib_calls': self.num_of_lib_calls})

        if not created:
            return function

        ExecutableWrapper(self.exe_signature, function).save()

        GraphWrapper(self.edges, self.blocks_data, self.num_of_blocks,
                     self.num_of_edges, function).save()

        instruction_wrappers = []
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
            instruction_wrappers.\
                append(InstructionWrapper(self.itypes[offset],
                                          offset, function,
                                          immediate,
                                          string,
                                          lib_call).instruction)
        Instruction.objects.bulk_create(instruction_wrappers)
        print "FunctionWrapper.save->"
        return function


class StringWrapper:
    def __init__(self, value):
        self.value = value

    def save(self):
        obj, created = String.objects.get_or_create(value=self.value)
        return obj


class LibraryCallWrapper:
    def __init__(self, name):
        self.name = name

    def save(self):
        obj, created = LibraryCall.objects.get_or_create(name=self.name)
        return obj


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
        obj, created = \
            Executable.objects.get_or_create(signature=self.signature)
        obj.functions.add(self.function)
        return obj


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


class UserWrapper:
    def __init__(self, user_name, password_hash):
        self.user_name = user_name
        self.password_hash = password_hash

    def save(self):
        obj, created = User.objects.\
            get_or_create(user_name=self.user_name,
                          defaults={'password_hash': self.password_hash})
        return obj


class DescriptionWrapper:
    def __init__(self, function_wrapper, description_data):
        self.function_wrapper = function_wrapper
        self.data = description_data["data"]
        self.user_name = description_data["user_name"]
        self.pass_hash = description_data["password_hash"]

    def save(self):
        user = UserWrapper(user_name=self.user_name,
                           password_hash=self.pass_hash).save()
        func = self.function_wrapper.save()
        obj, created = Description.objects.\
            get_or_create(data=self.data, function=func,
                          defaults={'user': user})
        return obj
