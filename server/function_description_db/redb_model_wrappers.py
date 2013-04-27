from models import (Function, Description, String, LibraryCall, Immediate,
                    Executable, Instruction, User, Graph)
import django.core.exceptions as exceptions


class FunctionWrapper:
    def __init__(self, attributes):
        self.first_addr = attributes["first_addr"]
        self.func_signature = attributes["func_signature"]
        self.frame_attributes = attributes["frame_attributes"]
        self.num_of_vars = attributes["num_of_vars"]
        self.itypes = attributes["itypes"]
        self.strings = attributes["strings"]
        self.library_calls = attributes["library_calls"]
        self.immediates = attributes["immediates"]
        self.exe_signature = attributes["exe_signature"]
        self.graph = attributes["graph"]

        self.num_of_args = self.frame_attributes["FrameArgsSize"]
        self.num_of_vars = self.frame_attributes["FrameLvarSize"]
        self.frame_size = self.frame_attributes["FrameSize"]

        self.init_all()

    def init_all(self):
        self.function = Function(self.first_addr,
                                 self.func_signature,
                                 self.num_of_args,
                                 self.num_of_vars,
                                 self.frame_size)

        self.executable_wrapper = ExecutableWrapper(self.exe_signature,
                                                    self.function)
        self.graph_wrapper = GraphWrapper(self.graph, self.function)

        self.instrucrion_wrappers = []
        self.string_wrappers = []
        self.lib_call_wrappers = []
        self.immediate_wrappers = []

        for offset in range(len(self.itypes)):
            instruction_wrapper = \
                InstructionWrapper(self.itypes[offset],
                                   offset,
                                   self.function)
            self.instrucrion_wrappers.append(instruction_wrapper)

            if offset in self.strings:
                string_wrapper =\
                    StringWrapper(self.strings[offset],
                                  self.function,
                                  instruction_wrapper.instruction)
                self.string_wrappers.append(string_wrapper)

            if offset in self.library_calls:
                lib_call_wrapper =\
                    LibraryCallWrapper(self.library_calls[offset],
                                       self.function,
                                       instruction_wrapper.instruction)
                self.lib_call_wrappers.append(lib_call_wrapper)

            if offset in self.immediates:
                immediate_wrapper =\
                    ImmediateWrapper(self.immediates[offset],
                                     self.function,
                                     instruction_wrapper.instruction)
                self.lib_call_wrappers.append(immediate_wrapper)

    def find_existing(self):
        try:
            return Function.objects.get(signature=self.func_signature)
        except exceptions.ObjectDoesNotExist:
            return None

    def save(self):
        self.function.save()

        existing_executable = self.executable_wrapper.find_existing()
        if(len(existing_executable) == 1):
            self.function.executable = existing_executable[0]
        else:
            self.executable_wrapper.save()

        self.graph_wrapper.save()

        for instruction_wrapper in self.instrucrion_wrappers:
            instruction_wrapper.save()

        for string_wrapper in self.string_wrappers:
            string_wrapper.save()

        for lib_call_wrapper in self.lib_call_wrappers:
            lib_call_wrapper.save()

        for immediate_wrapper in self.immediate_wrappers:
            immediate_wrapper.save()


class StringWrapper:
    def __init__(self, value, function, instruction):
        self.value = value
        self.function = function
        self.instruction = instruction
        self.string = String(self.value,
                             self.function,
                             self.instruction)

    def save(self):
        self.string.save()


class LibraryCallWrapper:
    def __init__(self, name, function, instruction):
        self.name = name
        self.function = function
        self.instruction = instruction
        self.library_call = LibraryCall(self.name,
                                        self.function,
                                        self.instruction)

    def save(self):
        self.library_call.save()


class ImmediateWrapper:
    def __init__(self, value, function, instruction):
        self.value = value
        self.function = function
        self.instruction = instruction
        self.immediate = Immediate(self.value,
                                   self.function,
                                   self.instruction)

    def save(self):
        self.immediate.save()


class GraphWrapper:
    def __init__(self, graph, function, itypes):
        self.edges = graph[1]
        self.block_bounds = graph[0]
        self.num_of_blocks = len(self.block_bounds)
        self.num_of_edges = len(self.edges)
        self.function = function
        self.itypes = itypes

        self.generate_blocks_data()

        self.graph = Graph(self.edges,
                           self.blocks_data,
                           self.num_of_blocks,
                           self.num_of_edges,
                           self.function)

    def generate_blocks_data(self):
        self.blocks_data = ""
        for (startEA, endEA) in self.block_bounds:
            data = ""
            temp_itypes = self.itypes[startEA: endEA + 1]
            for temp_itype in temp_itypes:
                data += (temp_itype % 256)
                if(temp_itype > 255):
                    data += (temp_itype / 256)
            self.blocks_data += data

    def save(self):
        self.graph.save()


class ExecutableWrapper:
    def __init__(self, signature, function):
        self.signature = signature
        self.function = function
        self.executable = Executable(self.signature,
                                     self.function)

    def save(self):
        self.executable.save()

    def find_existing(self):
        return Executable.objects.filter(signature=self.signature)


class InstructionWrapper:
    def __init__(self, itype, offset, function):
        self.itype = itype
        self.offset = offset
        self.function = function

        self.instruction = Instruction(self.itype,
                                       self.offset,
                                       self.function)

    def save(self):
        self.instruction.save()


class UserWrapper:
    def __init__(self, user_name, password_hash):
        self.user_name = user_name
        self.password_hash = password_hash
        self.user = User(self.user_name,
                         self.password_hash)

    def save(self):
        self.user.save()

    def find_existing(self):
        return User.objects.filter(name=self.user_name)


class DescriptionWrapper:
    def __init__(self, function_wrapper, description_data):
        self.function_wrapper = function_wrapper
        self.data = description_data["data"]
        self.user_wrapper = UserWrapper(description_data["user_name"],
                                        description_data["password_hash"])
        self.description = Description(self.function_wrapper.function,
                                       self.data)

    def save(self):
        existing_user = self.user_wrapper.find_existing()
        if(len(existing_user) == 1):
            self.description.user = existing_user[0]
        else:
            self.user_wrapper.save()

        existing_function = self.function_wrapper.find_existing()
        if(existing_function != None):
            self.description.function = existing_function
        else:
            self.function_wrapper.save()

        self.description.save()

    def find_existing(self):
        return self.function.description_set.\
            filter(data=self.data, function=self.description.function)
