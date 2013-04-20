from models import (Function, Description, String, LibraryCall,
                    Executable, Instruction, User, Graph)
import django.core.exceptions as exceptions


class FunctionWrapper:
    def __init__(self, attributes):
        self.first_addr = attributes["first_addr"]
        self.func_signature = attributes["func_signature"]
        self.num_of_args = attributes["num_of_args"]
        self.num_of_vars = attributes["num_of_vars"]
        self.itypes = attributes["itypes"]
        self.strings = attributes["strings"]
        self.library_calls = attributes["library_calls"]
        self.exe_signature = attributes["exe_signature"]
        self.graph = attributes["graph"]

        self.init_all()

    def init_all(self):
        self.executable_wrapper = ExecutableWrapper(self.exe_signature)
        self.instrucrion_wrappers = []

        self.function = Function(self.first_addr,
                                 self.func_signature,
                                 len(self.itypes),
                                 self.num_of_args,
                                 self.num_of_vars,
                                 self.self.executable_wrapper.executable)

        self.graph_wrapper = GraphWrapper(self.graph, self.function)

        for offset in range(len(self.itypes)):
            string = None
            library_call = None

            if offset in self.strings:
                string = self.strings[offset]
            if offset in self.library_calls:
                library_call = self.library_calls[offset]

            instruction_wrapper = \
                InstructionWrapper(self.itypes[offset],
                                   offset,
                                   self.function,
                                   string_value=string,
                                   library_call_name=library_call)
            self.instrucrion_wrappers.append(instruction_wrapper)

    def find_existing(self):
        try:
            return Function.objects.get(signature=self.func_signature)
        except exceptions.ObjectDoesNotExist:
            return None

    def save(self):
        existing_executable = self.executable_wrapper.find_existing()
        if(len(existing_executable) == 1):
            self.function.executable = existing_executable[0]
        else:
            self.executable_wrapper.save()

        self.function.save()

        self.graph_wrapper.save()

        for instruction_wrapper in self.instrucrion_wrappers:
            instruction_wrapper.save()


class StringWrapper:
    def __init__(self, value):
        self.value = value
        self.string = String(self.value)

    def save(self):
        self.string.save()

    def find_existing(self):
        return String.objects.filter(value=self.value)


class LibraryCallWrapper:
    def __init__(self, name):
        self.name = name
        self.library_call = LibraryCall(self.name)

    def save(self):
        self.library_call.save()

    def find_existing(self):
        return LibraryCall.objects.filter(name=self.name)


class GraphWrapper:
    def __init__(self, graph, function):
        self.edges = graph[1]
        self.blocks = graph[0]
        self.num_of_blocks = len(self.blocks)
        self.num_of_edges = len(self.edges)
        self.function = function

        self.generate_blocks_data()

        self.graph = Graph(self.edges,
                           self.blocks_data,
                           self.num_of_blocks,
                           self.num_of_edges,
                           self.function)

    def generate_blocks_data(self):
        # TODO
        pass

    def save(self):
        self.graph.save()


class ExecutableWrapper:
    def __init__(self, signature):
        self.signature = signature
        self.executable = Executable(self.signature)

    def save(self):
        self.executable.save()

    def find_existing(self):
        return Executable.objects.filter(signature=self.signature)


class InstructionWrapper:
    def __init__(self, itype, offset, function, string_value=None,
                 library_call_name=None):
        self.itype = itype
        self.offset = offset
        self.function = function

        self.string_wrapper = None
        self.library_call_wrapper = None

        string_model = None
        library_call_model = None

        if string_value != None:
            self.string_wrapper = StringWrapper(string_value)
            string_model = self.string_wrapper.string
        elif library_call_name != None:
            self.library_call_wrapper = LibraryCallWrapper(library_call_name)
            library_call_model = self.library_call_wrapper.library_call

        self.instruction = Instruction(self.itype,
                                       self.offset,
                                       self.function,
                                       string_model,
                                       library_call_model)

    def save(self):
        if (self.string_wrapper != None):
            existing_string = self.string_wrapper.find_existing()
            if(len(existing_string) == 1):
                self.instruction.string = existing_string[0]
            else:
                self.string_wrapper.save()
        if (self.library_call_wrapper != None):
            existing_library_call = self.library_call_wrapper.find_existing()
            if(len(existing_library_call) == 1):
                self.instruction.library_call = existing_library_call[0]
            else:
                self.library_call_wrapper.save()
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
