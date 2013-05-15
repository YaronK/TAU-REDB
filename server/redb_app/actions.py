import model_wrappers
from models import Function
from utils import (log, generate_blocks_data, _decode_dict)
from collections import Counter
from heuristics import DictionarySimilarity, GraphSimilarity
from json import loads, dumps
from redb_app.models import User

MAX_NUM_INSNS_DEVIATION = 0.15
MAX_NUM_BLOCKS_DEVIATION = 0.15
MAX_NUM_EDGES_DEVIATION = 0.15
MAX_NUM_STRINGS_DEVIATION = 0.15
MAX_NUM_LIBCALLS_DEVIATION = 0.15
MAX_VARS_SIZE_DEVIATION = 0.15
MAX_ARGS_SIZE_DEVIATION = 0.50
MAX_REGS_SIZE_DEVIATION = 0.50
# MAX_NUM_IMMS_DEVIATION = 0.15

ATTRIBUTES = ["func_signature",
              "frame_attributes",
              "itypes",
              "strings",
              "immediates",
              "library_calls",
              "exe_signature",
              "graph"]

QUERY_FIELDS = ["type",
                    "username",
                    "password",
                    "data"]

FILTERING_THRESHOLD = 0.8
MATCHING_THRESHOLD = 0.9


class Query:
    def __init__(self, http_post):
        self.query = loads(http_post.FILES['action'].read(),
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
        self.description_data = dumps(self.description_data,
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
        func_set.filter(num_of_insns__range=  # @IgnorePep8
                        (insns_num * (1 - MAX_NUM_INSNS_DEVIATION),
                         insns_num * (1 + MAX_NUM_INSNS_DEVIATION)))

        num_of_blocks = func_wrapper.num_of_blocks
        func_set.filter(graph__num_of_blocks__range=  # @IgnorePep8
                            (num_of_blocks * (1 - MAX_NUM_BLOCKS_DEVIATION),
                             num_of_blocks * (1 + MAX_NUM_BLOCKS_DEVIATION)))

        num_of_edges = func_wrapper.num_of_edges
        func_set.filter(graph__num_of_edges__range=  # @IgnorePep8
                            (num_of_edges * (1 - MAX_NUM_EDGES_DEVIATION),
                             num_of_edges * (1 + MAX_NUM_EDGES_DEVIATION)))

        num_of_strings = func_wrapper.num_of_strings
        func_set.filter(num_of_strings__range=  # @IgnorePep8
                            (num_of_strings * (1 - MAX_NUM_STRINGS_DEVIATION),
                            num_of_strings * (1 + MAX_NUM_STRINGS_DEVIATION)))

        num_of_libcalls = func_wrapper.num_of_lib_calls
        func_set.filter(num_of_lib_calls__range=  # @IgnorePep8
                            (num_of_libcalls *
                             (1 - MAX_NUM_LIBCALLS_DEVIATION),
                             num_of_libcalls *
                             (1 + MAX_NUM_LIBCALLS_DEVIATION)))

        vars_size = func_wrapper.vars_size
        func_set.filter(vars_size__range=  # @IgnorePep8
                            (vars_size * (1 - MAX_VARS_SIZE_DEVIATION),
                            vars_size * (1 + MAX_VARS_SIZE_DEVIATION)))

        args_size = func_wrapper.args_size
        func_set.filter(args_size__range=  # @IgnorePep8
                            (args_size * (1 - MAX_ARGS_SIZE_DEVIATION),
                            args_size * (1 + MAX_ARGS_SIZE_DEVIATION)))

        regs_size = func_wrapper.regs_size
        func_set.filter(regs_size__range=  # @IgnorePep8
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
        temp_func_libcalls_dict = Counter(func_wrapper.library_calls.values())
        temp_func_itypes_dict = Counter(func_wrapper.itypes)

        func_set = dict_filter(func_set, extract_itypes_list,
                                        temp_func_itypes_dict)

        func_set = dict_filter(func_set, extract_libcalls_list,
                                        temp_func_libcalls_dict)

        func_set = dict_filter(func_set, extract_strings_list,
                                        temp_func_strings_dict)

        self.filtered_function_set = func_set

    @log
    def matching_grade_filtering(self):
        self.matching_funcs = []
        for func in self.filtered_function_set:
            second_graph_edges = loads(func.graph.edges)
            second_graph_data = loads(func.graph.blocks_data)

            grade = GraphSimilarity(self.temp_function_wrapper.edges,
                                    self.temp_function_wrapper.blocks_data,
                                    second_graph_edges,
                                    second_graph_data).ratio()

            if (grade >= MATCHING_THRESHOLD):
                self.matching_funcs.append((func, grade))

    @log
    def get_descriptions(self):
        descriptions = []
        for (func, grade) in self.matching_funcs:
            for desc in func.description_set.all():
                print desc.data
                try:
                    desc_data = loads(desc.data, object_hook=_decode_dict)
                except Exception as e:
                    print e

                descriptions.append({"func_id": func.id,
                                     "desc_num_of_insns": func.num_of_insns,
                                     "grade": grade,
                                     "updated_at": desc.updated_at.ctime(),
                                     "created_by": desc.user.user_name,
                                     "data": desc_data})
        return descriptions


@log
def general_process_attributes(attributes):
    pro_attrs = {}

    pro_attrs["func_signature"] = attributes["func_signature"]
    pro_attrs["itypes"] = attributes["itypes"]
    pro_attrs["strings"] = attributes["strings"]
    pro_attrs["library_calls"] = attributes["library_calls"]
    pro_attrs["immediates"] = attributes["immediates"]
    # pro_attrs["num_of_imms"] = len(pro_attrs["immediates"])
    pro_attrs["exe_signature"] = attributes["exe_signature"]
    pro_attrs["num_of_insns"] = len(pro_attrs["itypes"])

    frame_attributes = attributes["frame_attributes"]
    pro_attrs["args_size"] = frame_attributes["args_size"]
    pro_attrs["vars_size"] = frame_attributes["vars_size"]
    pro_attrs["regs_size"] = frame_attributes["regs_size"]
    pro_attrs["frame_size"] = frame_attributes["frame_size"]

    pro_attrs["num_of_strings"] = len(pro_attrs["strings"])
    pro_attrs["num_of_lib_calls"] = len(pro_attrs["library_calls"])

    graph = attributes["graph"]
    block_bounds = graph["block_bounds"]
    pro_attrs["edges"] = graph["edges"]
    pro_attrs["num_of_blocks"] = len(block_bounds)
    pro_attrs["num_of_edges"] = len(pro_attrs["edges"])
    pro_attrs["blocks_data"] = generate_blocks_data(block_bounds,
                                                    pro_attrs["itypes"])
    return pro_attrs


@log
def general_temp_function(attributes):
    return model_wrappers.FunctionWrapper(attributes)


@log
def extract_strings_list(function):
    instruction_set = function.instruction_set.exclude(string=None)
    return [instruction.string.value for instruction in instruction_set]


@log
def extract_libcalls_list(function):
    instruction_set = function.instruction_set.exclude(lib_call=None)
    return [instruction.lib_call.name for instruction in instruction_set]


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
