import model_wrappers
from models import Function
from utils import (log, generate_blocks, _decode_dict)
from collections import Counter
from heuristics import DictionarySimilarity, GraphSimilarity
import json
import graph
from redb_app.models import User

MAX_NUM_INSNS_DEVIATION = 0.15
MAX_NUM_BLOCKS_DEVIATION = 0.15
MAX_NUM_EDGES_DEVIATION = 0.15
MAX_NUM_STRINGS_DEVIATION = 0.15
MAX_NUM_CALLS_DEVIATION = 0.15
MAX_VARS_SIZE_DEVIATION = 0.15
MAX_ARGS_SIZE_DEVIATION = 0.50
MAX_REGS_SIZE_DEVIATION = 0.50
# MAX_NUM_IMMS_DEVIATION = 0.15

ATTRIBUTES = ["func_signature",
              "frame_attributes",
              "itypes",
              "strings",
              "immediates",
              "calls",
              "exe_signature",
              "exe_name",
              "graph"]

QUERY_FIELDS = ["type",
                    "username",
                    "password",
                    "data"]

FILTERING_THRESHOLD = 0.8
MATCHING_THRESHOLD = 0.9


class Query:
    def __init__(self, http_post):
        self.query = json.loads(http_post.FILES['action'].read(),
                          object_hook=_decode_dict)

    def check_validity(self):
        if not (set(self.query.keys()) == set(QUERY_FIELDS)):
            raise "Missing query field(s) / Too many query fields."

    def process(self):
        for attr in self.query:
            setattr(self, attr, self.query[attr])

    def authenticate_user(self):
        User.objects.get(user_name=self.username,
                         password_hash=self.password)


class SubmitAction:
    @log
    def __init__(self, data, username):
        self.attributes = data["attributes"]
        self.description_data = data["description"]
        self.username = username
        self.temp_function_wrapper = None
        self.temp_description_wrapper = None
        self.filtered_function_set = None

    @log
    def check_validity(self):
        if not (set(self.attributes.keys()) == set(ATTRIBUTES)):
            raise "Missing attribute(s) / Too many attributes."

    @log
    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    @log
    def temp_function(self):
        self.temp_function_wrapper = general_temp_function(self.attributes)

    @log
    def process_description(self):
        self.description_data = json.dumps(self.description_data,
                                              ensure_ascii=False)

    @log
    def insert_description(self):
        model_wrappers.DescriptionWrapper(self.temp_function_wrapper,
                                          self.description_data,
                                          self.username).save()


class RequestAction:
    @log
    def __init__(self, data):
        self.attributes = data["attributes"]
        self.temp_function_wrapper = None

    @log
    def check_validity(self):
        if not (set(self.attributes.keys()) == set(ATTRIBUTES)):
            raise "Missing attribute(s) / Too many attributes."

    @log
    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    @log
    def temp_function(self):
        self.temp_function_wrapper = general_temp_function(self.attributes)

    @log
    def db_filtering(self):
        func_wrapper = self.temp_function_wrapper
        func_set = Function.objects

        insns_num = func_wrapper.num_of_insns
        func_set.filter(num_of_insns__range=# @IgnorePep8
                        (insns_num * (1 - MAX_NUM_INSNS_DEVIATION),
                         insns_num * (1 + MAX_NUM_INSNS_DEVIATION)))

        num_of_blocks = func_wrapper.num_of_blocks
        func_set.filter(graph__num_of_blocks__range=# @IgnorePep8
                            (num_of_blocks * (1 - MAX_NUM_BLOCKS_DEVIATION),
                             num_of_blocks * (1 + MAX_NUM_BLOCKS_DEVIATION)))

        num_of_edges = func_wrapper.num_of_edges
        func_set.filter(graph__num_of_edges__range=# @IgnorePep8
                            (num_of_edges * (1 - MAX_NUM_EDGES_DEVIATION),
                             num_of_edges * (1 + MAX_NUM_EDGES_DEVIATION)))

        num_of_strings = func_wrapper.num_of_strings
        func_set.filter(num_of_strings__range=# @IgnorePep8
                            (num_of_strings * (1 - MAX_NUM_STRINGS_DEVIATION),
                            num_of_strings * (1 + MAX_NUM_STRINGS_DEVIATION)))

        num_of_calls = func_wrapper.num_of_calls
        func_set.filter(num_of_calls__range=# @IgnorePep8
                            (num_of_calls *
                             (1 - MAX_NUM_CALLS_DEVIATION),
                             num_of_calls *
                             (1 + MAX_NUM_CALLS_DEVIATION)))

        vars_size = func_wrapper.vars_size
        func_set.filter(vars_size__range=# @IgnorePep8
                            (vars_size * (1 - MAX_VARS_SIZE_DEVIATION),
                            vars_size * (1 + MAX_VARS_SIZE_DEVIATION)))

        args_size = func_wrapper.args_size
        func_set.filter(args_size__range=# @IgnorePep8
                            (args_size * (1 - MAX_ARGS_SIZE_DEVIATION),
                            args_size * (1 + MAX_ARGS_SIZE_DEVIATION)))

        regs_size = func_wrapper.regs_size
        func_set.filter(regs_size__range=# @IgnorePep8
                            (regs_size * (1 - MAX_REGS_SIZE_DEVIATION),
                            regs_size * (1 + MAX_REGS_SIZE_DEVIATION)))

        """
        num_of_imms = func_wrapper.num_of_imms
        func_set.filter(num_of_imms__range=  # @IgnorePep8
                            (num_of_imms * (1 - MAX_NUM_IMMS_DEVIATION),
                            num_of_imms * (1 + MAX_NUM_IMMS_DEVIATION)))
        """

        self.filtered_function_set = func_set.all()

    @log
    def dictionaries_filtering(self):
        func_wrapper = self.temp_function_wrapper
        func_set = self.filtered_function_set
        temp_func_strings_dict = Counter(func_wrapper.strings.values())
        temp_func_calls_dict = Counter(func_wrapper.calls.values())
        temp_func_itypes_dict = Counter(func_wrapper.itypes)

        func_set = dict_filter(func_set, extract_itypes_list,
                                        temp_func_itypes_dict)

        func_set = dict_filter(func_set, extract_calls_list,
                                        temp_func_calls_dict)

        func_set = dict_filter(func_set, extract_strings_list,
                                        temp_func_strings_dict)

        self.filtered_function_set = func_set

    @log
    def matching_grade_filtering(self):
        self.matching_funcs = []
        temp_func_blocks = \
            generate_temp_func_blocks(self.temp_function_wrapper)

        temp_func_graph = graph.Graph(temp_func_blocks,
                                      self.temp_function_wrapper.edges)

        for func in self.filtered_function_set:
            second_graph_edges = json.loads(func.graph.edges)
            second_func_blocks = \
                generate_db_func_blocks(func)

            second_graph = graph.Graph(second_func_blocks, second_graph_edges)
            grade = GraphSimilarity(temp_func_graph, second_graph).ratio()

            if (grade >= MATCHING_THRESHOLD):
                self.matching_funcs.append((func, grade))

    @log
    def get_descriptions(self):
        descriptions = []
        exe_names = ""
        print self.matching_funcs
        for (func, grade) in self.matching_funcs:
            for exe in func.executable_set.all():
                exe_names = exe.names + exe_names
                print exe_names
            for desc in func.description_set.all():
                print desc.data
                try:
                    desc_data = json.loads(desc.data, object_hook=_decode_dict)
                except Exception as e:
                    print e

                descriptions.append({"func_id": func.id,
                                     "desc_num_of_insns": func.num_of_insns,
                                     "grade": grade,
                                     "updated_at": desc.updated_at.ctime(),
                                     "created_by": desc.user.user_name,
                                     "data": desc_data,
                                     "exe_names": exe_names})
        return descriptions


@log
def general_process_attributes(attributes):
    pro_attrs = {}

    pro_attrs["func_signature"] = attributes["func_signature"]
    pro_attrs["itypes"] = attributes["itypes"]
    pro_attrs["strings"] = attributes["strings"]
    pro_attrs["calls"] = attributes["calls"]
    pro_attrs["immediates"] = attributes["immediates"]
    # pro_attrs["num_of_imms"] = len(pro_attrs["immediates"])
    pro_attrs["exe_signature"] = attributes["exe_signature"]
    pro_attrs["exe_name"] = attributes["exe_name"]
    pro_attrs["num_of_insns"] = len(pro_attrs["itypes"])

    frame_attributes = attributes["frame_attributes"]
    pro_attrs["args_size"] = frame_attributes["args_size"]
    pro_attrs["vars_size"] = frame_attributes["vars_size"]
    pro_attrs["regs_size"] = frame_attributes["regs_size"]
    pro_attrs["frame_size"] = frame_attributes["frame_size"]

    pro_attrs["num_of_strings"] = len(pro_attrs["strings"])
    pro_attrs["num_of_calls"] = len(pro_attrs["calls"])

    graph = attributes["graph"]
    block_bounds = graph["block_bounds"]
    pro_attrs["blocks_bounds"] = block_bounds
    pro_attrs["edges"] = graph["edges"]
    pro_attrs["num_of_blocks"] = len(block_bounds)
    pro_attrs["num_of_edges"] = len(pro_attrs["edges"])

    return pro_attrs


@log
def general_temp_function(attributes):
    return model_wrappers.FunctionWrapper(attributes)


@log
def extract_strings_list(function):
    instruction_set = function.instruction_set.exclude(string=None)
    return [instruction.string.value for instruction in instruction_set]


@log
def extract_calls_list(function):
    instruction_set = function.instruction_set.exclude(call=None)
    return [instruction.call.name for instruction in instruction_set]


@log
def extract_itypes_list(function):
    instruction_set = function.instruction_set.all()
    return [instruction.itype for instruction in instruction_set]


@log
def dict_filter(func_set, list_extraction_function, ref_dict):
    filtered_functions = []
    for func in func_set:
        func_dict = Counter(list_extraction_function(func))
        grade = DictionarySimilarity(func_dict, ref_dict).ratio()
        if (grade >= FILTERING_THRESHOLD):
            filtered_functions.append(func)
    return filtered_functions


@log
def generate_temp_func_blocks(function_wrapper):
    temp_func_itypes = function_wrapper.itypes
    temp_func_strings = []
    temp_func_calls = []
    temp_func_imms = []

    for offset in range(len(function_wrapper.itypes)):
        str_offset = str(offset)
        if str_offset in function_wrapper.strings:
            temp_func_strings.append(function_wrapper.strings[str_offset])
        else:
            temp_func_strings.append(None)

        if str_offset in function_wrapper.calls:
            temp_func_calls.append(function_wrapper.calls[str_offset])
        else:
            temp_func_calls.append(None)

        if str_offset in function_wrapper.immediates:
            temp_func_imms.append(function_wrapper.immediates[str_offset])
        else:
            temp_func_imms.append(None)

    return generate_blocks(function_wrapper.blocks_bounds,
                           temp_func_itypes,
                           temp_func_strings,
                           temp_func_calls,
                           temp_func_imms)


@log
def generate_db_func_blocks(function):
    strings = {}
    calls = {}
    immediates = {}
    itypes = {}
    instruction_set = function.instruction_set.all()
    blocks_bounds = json.loads(function.graph.blocks_bounds)

    for instruction in instruction_set:
        itypes[instruction.offset] = instruction.itype

        if instruction.string == None:
            strings[instruction.offset] = None
        else:
            strings[instruction.offset] = instruction.string.value

        if instruction.call == None:
            calls[instruction.offset] = None
        else:
            calls[instruction.offset] = instruction.call.name

        if instruction.immediate == None:
            immediates[instruction.offset] = None
        else:
            immediates[instruction.offset] = instruction.immediate

    return generate_blocks(blocks_bounds,
                           itypes.values(),
                           strings.values(),
                           calls.values(),
                           immediates.values())
