from models import Function, Description
import utils
from collections import Counter
from heuristics import DictionarySimilarity, GraphSimilarity
import json
from redb_app.utils import _decode_dict

MAX_NUM_INSNS_DEVIATION = 0.15
MAX_NUM_BLOCKS_DEVIATION = 0.15
MAX_NUM_EDGES_DEVIATION = 0.15
MAX_NUM_STRINGS_DEVIATION = 0.15
MAX_NUM_CALLS_DEVIATION = 0.15
MAX_VARS_SIZE_DEVIATION = 0.15
MAX_ARGS_SIZE_DEVIATION = 0.50
MAX_REGS_SIZE_DEVIATION = 0.50
MAX_NUM_IMMS_DEVIATION = 0.15

ATTRIBUTES = ["func_signature",
              "func_name",
              "frame_attributes",
              "itypes",
              "strings",
              "immediates",
              "calls",
              "exe_signature",
              "exe_name",
              "graph"]

FILTERING_THRESHOLD = 0.8
MATCHING_THRESHOLD = 0.9


class Query:
    def __init__(self, request):
        self.request = request

    def check_validity(self):
        query_dict = self.request.POST

        if not 'type' in query_dict:
            raise Exception("Missing query type.")

        query_type = json.loads(query_dict['type'])

        if not query_type in ["request", "submit"]:
            raise Exception("Unknown query type.")

        return query_type


class SubmitAction:
    def __init__(self, request):
        query_dict = request.POST
        if not 'attributes' in query_dict:
            raise Exception("submit is missing attributes.")
        if not 'description' in query_dict:
            raise Exception("submit is missing description.")

        self.attributes = json.loads(query_dict["attributes"],
                                     object_hook=utils._decode_dict)
        self.description = json.loads(query_dict["description"],
                                     object_hook=utils._decode_dict)
        self.user = request.user

    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    def temp_function(self):
        self.function = generate_function(self.attributes)

    def process_description(self):
        self.description_data = json.dumps(self.description,
                                           ensure_ascii=False)

    def insert_description(self):
        try:
            self.function = Function.objects.\
                get(signature=self.attributes["func_signature"])
        except Function.DoesNotExist:
            self.function.save()
        description = Description()
        description.initialize(self.function, self.description_data,
                                self.user)
        description.save()


class RequestAction:
    def __init__(self, request):
        self.user = request.user

        query_dict = request.POST
        if not 'attributes' in query_dict:
            raise Exception("request is missing attributes.")

        self.attributes = json.loads(query_dict["attributes"],
                                     encoding='ISO-8859-1',
                                     object_hook=_decode_dict)

        if not (set(self.attributes.keys()) == set(ATTRIBUTES)):
            raise Exception("Missing attribute(s) / Too many attributes.")

    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    def temp_function(self):
        self.function = generate_function(self.attributes)

    def db_filtering(self):
        func = self.function
        func_set = Function.objects

        insns_num = func.num_of_insns
        func_set.filter(num_of_insns__range=  # @IgnorePep8
                        (insns_num * (1 - MAX_NUM_INSNS_DEVIATION),
                         insns_num * (1 + MAX_NUM_INSNS_DEVIATION)))

        num_of_blocks = func.graph.num_of_blocks
        func_set.filter(graph__num_of_blocks__range=  # @IgnorePep8
                            (num_of_blocks * (1 - MAX_NUM_BLOCKS_DEVIATION),
                             num_of_blocks * (1 + MAX_NUM_BLOCKS_DEVIATION)))

        num_of_edges = func.graph.num_of_edges
        func_set.filter(graph__num_of_edges__range=  # @IgnorePep8
                            (num_of_edges * (1 - MAX_NUM_EDGES_DEVIATION),
                             num_of_edges * (1 + MAX_NUM_EDGES_DEVIATION)))

        num_of_strings = func.num_of_strings
        func_set.filter(num_of_strings__range=  # @IgnorePep8
                            (num_of_strings * (1 - MAX_NUM_STRINGS_DEVIATION),
                            num_of_strings * (1 + MAX_NUM_STRINGS_DEVIATION)))

        num_of_calls = func.num_of_calls
        func_set.filter(num_of_calls__range=  # @IgnorePep8
                            (num_of_calls *
                             (1 - MAX_NUM_CALLS_DEVIATION),
                             num_of_calls *
                             (1 + MAX_NUM_CALLS_DEVIATION)))

        vars_size = func.vars_size
        func_set.filter(vars_size__range=  # @IgnorePep8
                            (vars_size * (1 - MAX_VARS_SIZE_DEVIATION),
                            vars_size * (1 + MAX_VARS_SIZE_DEVIATION)))

        args_size = func.args_size
        func_set.filter(args_size__range=  # @IgnorePep8
                            (args_size * (1 - MAX_ARGS_SIZE_DEVIATION),
                            args_size * (1 + MAX_ARGS_SIZE_DEVIATION)))

        regs_size = func.regs_size
        func_set.filter(regs_size__range=  # @IgnorePep8
                            (regs_size * (1 - MAX_REGS_SIZE_DEVIATION),
                            regs_size * (1 + MAX_REGS_SIZE_DEVIATION)))

        num_of_imms = func.num_of_imms
        func_set.filter(num_of_imms__range=  # @IgnorePep8
                            (num_of_imms * (1 - MAX_NUM_IMMS_DEVIATION),
                            num_of_imms * (1 + MAX_NUM_IMMS_DEVIATION)))

        self.filtered_function_set = func_set.all()

    def dictionaries_filtering(self):
        func_set = self.filtered_function_set
        temp_func_itypes_dict = Counter(self.attributes["itypes"])
        func_set = dict_filter(func_set, extract_itypes_list,
                               temp_func_itypes_dict)
        self.filtered_function_set = func_set

    def matching_grade_filtering(self):
        self.matching_funcs = []
        temp_graph_nx = \
            self.function.graph.get_data()

        for func in self.filtered_function_set:
            second_graph_nx = func.graph_set.all()[0].get_data()
            grade = GraphSimilarity(temp_graph_nx, second_graph_nx).ratio()
            if (grade >= MATCHING_THRESHOLD):
                self.matching_funcs.append((func, grade))

    def get_descriptions(self):
        descriptions = []
        exe_names = ""
        for (func, grade) in self.matching_funcs:
            for exe in func.executable_set.all():
                exe_names = exe.names + exe_names
            for desc in func.description_set.all():
                try:
                    desc_data = json.loads(desc.data,
                                           object_hook=utils._decode_dict)
                except Exception as e:
                    print e

                descriptions.append({"func_id": func.id,
                                     "desc_num_of_insns": func.num_of_insns,
                                     "grade": grade,
                                     "updated_at": desc.updated_at.ctime(),
                                     "created_by": desc.user.username,
                                     "data": desc_data,
                                     "exe_names": exe_names})
        return descriptions


def general_process_attributes(attributes):
    pro_attrs = {}
    pro_attrs["func_signature"] = attributes["func_signature"]
    pro_attrs["func_name"] = attributes["func_name"]
    pro_attrs["itypes"] = attributes["itypes"]
    pro_attrs["strings"] = attributes["strings"]
    pro_attrs["calls"] = attributes["calls"]
    pro_attrs["immediates"] = attributes["immediates"]
    pro_attrs["num_of_imms"] = len(pro_attrs["immediates"])
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
    pro_attrs["block_bounds"] = graph["block_bounds"]
    pro_attrs["edges"] = graph["edges"]

    return pro_attrs


def generate_function(attributes):
    function = Function()
    function.initialize(attributes["func_signature"],
                        attributes["exe_signature"],
                        attributes["args_size"],
                        attributes["vars_size"],
                        attributes["regs_size"],
                        attributes["frame_size"],
                        attributes["num_of_strings"],
                        attributes["num_of_calls"],
                        attributes["num_of_imms"],
                        attributes["num_of_insns"],
                        attributes["func_name"],
                        attributes["exe_name"],
                        attributes["immediates"],
                        attributes["strings"],
                        attributes["itypes"],
                        attributes["calls"],
                        attributes["block_bounds"],
                        attributes["edges"])
    return function


def extract_strings_list(function):
    block_set = function.graph_set.all()[0].block_set.all()
    strings = []
    for block in block_set:
        strings.append(instruction.string.value for instruction in
                       block.instruction_set.exclude(string=None))
    return strings


def extract_calls_list(function):
    block_set = function.graph_set.all()[0].block_set.all()
    calls = []
    for block in block_set:
        calls.append(instruction.call.name for instruction in
                     block.instruction_set.exclude(call=None))
    return calls


def extract_itypes_list(function):
    block_set = function.graph_set.all()[0].block_set.all()
    itypes = []
    for block in block_set:
        for instruction in block.instruction_set.all():
            itypes.append(instruction.itype)
    return itypes


def dict_filter(func_set, list_extraction_function, ref_dict):
    filtered_functions = []
    for func in func_set:
        func_dict = Counter(list_extraction_function(func))
        grade = DictionarySimilarity(func_dict, ref_dict).ratio()
        if (grade >= FILTERING_THRESHOLD):
            filtered_functions.append(func)
    return filtered_functions
