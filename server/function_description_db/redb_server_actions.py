import redb_model_wrappers
from function_description_db.models import Function
from redb_server_utils import (log_calls_decorator,
                               generate_blocks_data)

MAX_NUM_INSNS_DEVIATION = 0.15
MAX_NUM_BLOCKS_DEVIATION = 0.15
MAX_NUM_EDGES_DEVIATION = 0.15
MAX_NUM_STRINGS_DEVIATION = 0.15
MAX_NUM_LIBCALLS_DEVIATION = 0.15

ATTRIBUTES = ["func_signature",
              "frame_attributes",
              "itypes",
              "strings",
              "immediates",
              "library_calls",
              "exe_signature",
              "graph"]

DESCRIPTION_DATA = ["data",
                    "user_name",
                    "password_hash"]


class SubmitAction:
    @log_calls_decorator
    def __init__(self, attributes, description_data):
        self.attributes = attributes
        self.description_data = description_data
        self.temp_function_wrapper = None
        self.temp_description_wrapper = None
        self.filtered_function_set = None

    @log_calls_decorator
    def check_validity(self):
        all_attributes_exist(self.attributes)
        all_description_items_exist(self.description_data)

    @log_calls_decorator
    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    @log_calls_decorator
    def temp_function(self):
        self.temp_function_wrapper = general_temp_function(self.attributes)

    @log_calls_decorator
    def insert_description(self):
        redb_model_wrappers.DescriptionWrapper(self.temp_function_wrapper,
                                               self.description_data).save()


class RequestAction:
    @log_calls_decorator
    def __init__(self, attributes):
        self.attributes = attributes
        self.temp_function_wrapper = None

    @log_calls_decorator
    def check_validity(self):
        all_attributes_exist(self.attributes)

    @log_calls_decorator
    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    @log_calls_decorator
    def temp_function(self):
        self.temp_function_wrapper = general_temp_function(self.attributes)

    @log_calls_decorator
    def filter_functions(self):
        func_wrapper = self.temp_function_wrapper
        func_set = Function.objects.all()

        insns_num = len(func_wrapper.itypes)
        func_set = \
            func_set.filter(insctruction_set__count__range=  # @IgnorePep8
                            (insns_num * (1 - MAX_NUM_INSNS_DEVIATION),
                             insns_num * (1 + MAX_NUM_INSNS_DEVIATION)))

        num_of_blocks = func_wrapper.num_of_blocks
        func_set = \
            func_set.filter(graph__num_of_blocks__range=  # @IgnorePep8
                            (num_of_blocks * (1 - MAX_NUM_BLOCKS_DEVIATION),
                             num_of_blocks * (1 + MAX_NUM_BLOCKS_DEVIATION)))

        num_of_edges = func_wrapper.num_of_edges
        func_set = \
            func_set.filter(graph__num_of_edges__range=  # @IgnorePep8
                            (num_of_edges * (1 - MAX_NUM_EDGES_DEVIATION),
                             num_of_edges * (1 + MAX_NUM_EDGES_DEVIATION)))

        num_of_strings = func_wrapper.num_of_strings
        func_set = \
            func_set.filter(string_set__count__range=  # @IgnorePep8
                            (num_of_strings * (1 - MAX_NUM_STRINGS_DEVIATION),
                            num_of_strings * (1 + MAX_NUM_STRINGS_DEVIATION)))

        num_of_libcalls = func_wrapper.num_of_lib_calls
        func_set = \
            func_set.filter(librarycall_set__count__range=  # @IgnorePep8
                            (num_of_libcalls *
                             (1 - MAX_NUM_LIBCALLS_DEVIATION),
                             num_of_libcalls *
                             (1 + MAX_NUM_LIBCALLS_DEVIATION)))

        self.filtered_function_set = func_set

    @log_calls_decorator
    def get_descriptions(self):
        pass


@log_calls_decorator
def all_attributes_exist(attributes):
    for attribute_name in ATTRIBUTES:
        if attribute_name not in attributes:
            raise ("REDB: required attribute" + attribute_name +
                   "was not found")


@log_calls_decorator
def all_description_items_exist(description_data):
    for description_item in DESCRIPTION_DATA:
        if description_item not in description_data:
            raise ("REDB: required description_item" + description_item +
                   "was not found")


@log_calls_decorator
def general_process_attributes(attributes):
    pro_attrs = {}

    pro_attrs["func_signature"] = attributes["func_signature"]
    pro_attrs["itypes"] = attributes["itypes"]
    pro_attrs["strings"] = attributes["strings"]
    pro_attrs["library_calls"] = attributes["library_calls"]
    pro_attrs["immediates"] = attributes["immediates"]
    pro_attrs["exe_signature"] = attributes["exe_signature"]

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


@log_calls_decorator
def general_temp_function(attributes):
    return redb_model_wrappers.FunctionWrapper(attributes)
