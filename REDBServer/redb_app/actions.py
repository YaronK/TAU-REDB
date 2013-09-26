# Python
from collections import Counter
import json

# REDB
import utils
from models import Function, Description
from heuristics import DictionarySimilarity, GraphSimilarity, FrameSimilarity
import constants
import math


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
        if self.attributes["num_of_insns"] <= 1:
            return 0
        return 1

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
        description.initialize(self.function, self.description_data, self.user)
        description.save()


class RequestAction:
    def __init__(self, request):
        self.user = request.user

        query_dict = request.POST
        if not 'attributes' in query_dict:
            raise Exception("request is missing attributes.")

        self.attributes = json.loads(query_dict["attributes"],
                                     encoding='ISO-8859-1',
                                     object_hook=utils._decode_dict)

        if not (set(self.attributes.keys()) ==
                set(constants.REQUIRED_ATTRIBUTES)):
            raise Exception("Missing attribute(s) / Too many attributes.")

    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    def temp_function(self):
        self.function = generate_function(self.attributes)

    def db_filtering(self):
        func = self.function
        func_set = Function.objects

        func_set = RequestAction.insns_num_filter(func, func_set)
        func_set = RequestAction.blocks_num_filter(func, func_set)
        func_set = RequestAction.edges_num_filter(func, func_set)
        func_set = RequestAction.vars_size_filter(func, func_set)
        func_set = RequestAction.args_size_filter(func, func_set)
        func_set = RequestAction.regs_size_filter(func, func_set)
        func_set = RequestAction.calls_num_filter(func, func_set)
        func_set = RequestAction.strings_num_filter(func, func_set)
        func_set = RequestAction.imms_num_filter(func, func_set)

        self.filtered_function_set = func_set.all()

    @classmethod
    def get_bounds(mean, deviation):
        lower_bound = math.floor(mean * (1 - deviation))
        upper_bound = math.ceil(mean * (1 + deviation))
        return lower_bound, upper_bound

    @classmethod
    def insns_num_filter(cls, func, func_set):
        insns_num = func.num_of_insns
        deviation = constants.db_filter.MAX_NUM_INSNS_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(insns_num, deviation)
        func_set = func_set.filter(num_of_insns__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def blocks_num_filter(cls, func, func_set):
        num_of_blocks = func.graph.num_of_blocks
        deviation = constants.db_filter.MAX_NUM_BLOCKS_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(num_of_blocks, deviation)
        func_set = func_set.filter(graph__num_of_blocks__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def edges_num_filter(cls, func, func_set):
        num_of_edges = func.graph.num_of_edges
        deviation = constants.db_filter.MAX_NUM_EDGES_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(num_of_edges, deviation)
        func_set = func_set.filter(graph__num_of_edges__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def vars_size_filter(cls, func, func_set):
        vars_size = func.vars_size
        deviation = constants.db_filter.MAX_VARS_SIZE_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(vars_size, deviation)
        func_set = func_set.filter(vars_size__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def args_size_filter(cls, func, func_set):
        args_size = func.args_size
        deviation = constants.db_filter.MAX_ARGS_SIZE_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(args_size, deviation)
        func_set = func_set.filter(args_size__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def regs_size_filter(cls, func, func_set):
        regs_size = func.regs_size
        deviation = constants.db_filter.MAX_REGS_SIZE_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(regs_size, deviation)
        func_set = func_set.filter(regs_size__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def calls_num_filter(cls, func, func_set):
        num_of_calls = func.num_of_calls
        deviation = constants.db_filter.MAX_NUM_CALLS_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(num_of_calls, deviation)
        func_set = func_set.filter(num_of_calls__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def strings_num_filter(cls, func, func_set):
        num_of_strings = func.num_of_strings
        deviation = constants.db_filter.MAX_NUM_STRINGS_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(num_of_strings, deviation)
        func_set = func_set.filter(num_of_strings__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    @classmethod
    def imms_num_filter(cls, func, func_set):
        num_of_imms = func.num_of_imms
        deviation = constants.db_filter.MAX_NUM_IMMS_DEVIATION
        lower_bound, upper_bound = cls.get_bounds(num_of_imms, deviation)
        func_set = func_set.filter(num_of_imms__range=  # @IgnorePep8
                                   (lower_bound, upper_bound))
        return func_set

    def dictionary_filtering(self):
        function_set = self.filtered_function_set

        reference_itypes_dict = Counter(self.attributes["itypes"])
        function_set = dict_filter_by_single_attr(function_set,
                                   extract_itypes_list_function,
                                   reference_itypes_dict,
                                   constants.dict_filter.ITYPES_THRESHOLD)

        self.filtered_function_set = function_set

    def matching_grade_filtering(self):
        self.matching_funcs = []
        temp_graph_nx = self.function.graph.get_data()

        for func in self.filtered_function_set:
            second_graph_nx = func.graph_set.all()[0].get_data()
            graph_simialrity_grade = \
                GraphSimilarity(temp_graph_nx, second_graph_nx).ratio()
            frame_similarity = \
                FrameSimilarity(self.function.args_size,
                                          self.function.vars_size,
                                          self.function.regs_size,
                                          func.args_size,
                                          func.vars_size,
                                          func.regs_size).ratio()

            grade = (constants.matching_grade.GRAPH_SIMILARITY_WEIGHT *
                     graph_simialrity_grade +
                     constants.matching_grade.FRAME_SIMILARITY_WEIGHT *
                     frame_similarity)
            if (grade >= constants.matching_grade.MATCHING_THRESHOLD):
                self.matching_funcs.append((func, grade))

    def get_descriptions(self):
        descriptions = []
        exe_names = ""
        for (func, grade) in self.matching_funcs:
            for exe in func.executable_set.all():
                exe_names += exe.names
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
    temp_attributes = {}

    temp_attributes["func_signature"] = attributes["func_signature"]
    temp_attributes["func_name"] = attributes["func_name"]

    temp_attributes["exe_signature"] = attributes["exe_signature"]
    temp_attributes["exe_name"] = attributes["exe_name"]

    temp_attributes["itypes"] = attributes["itypes"]
    temp_attributes["num_of_insns"] = len(temp_attributes["itypes"])

    temp_attributes["strings"] = attributes["strings"]
    temp_attributes["num_of_strings"] = len(temp_attributes["strings"])

    temp_attributes["calls"] = attributes["calls"]
    temp_attributes["num_of_calls"] = len(temp_attributes["calls"])

    temp_attributes["immediates"] = attributes["immediates"]
    temp_attributes["num_of_imms"] = len(temp_attributes["immediates"])

    frame_attributes = attributes["frame_attributes"]
    temp_attributes["args_size"] = frame_attributes["args_size"]
    temp_attributes["vars_size"] = frame_attributes["vars_size"]
    temp_attributes["regs_size"] = frame_attributes["regs_size"]
    temp_attributes["frame_size"] = frame_attributes["frame_size"]

    graph = attributes["graph"]
    temp_attributes["block_bounds"] = graph["block_bounds"]
    temp_attributes["edges"] = graph["edges"]

    return temp_attributes


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


def extract_itypes_list_function(function):
    instruction_set = function.instruction_set.all()
    return [instruction.itype for instruction in instruction_set]


def dict_filter_by_single_attr(func_set, list_extraction_function, ref_dict,
                               threshold):
    filtered_functions = []
    for func in func_set:
        func_dict = Counter(list_extraction_function(func))
        grade = DictionarySimilarity(func_dict, ref_dict).ratio()
        if (grade >= threshold):
            filtered_functions.append(func)
    return filtered_functions
