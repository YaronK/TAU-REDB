import model_wrappers
from models import Function
import utils
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
              "func_name",
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
                          object_hook=utils._decode_dict)

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
    @utils.log
    def __init__(self, data, username):
        self.attributes = data["attributes"]
        self.description_data = data["description"]
        self.username = username
        self.temp_function_wrapper = None
        self.temp_description_wrapper = None
        self.filtered_function_set = None

    @utils.log
    def check_validity(self):
        if not (set(self.attributes.keys()) == set(ATTRIBUTES)):
            raise "Missing attribute(s) / Too many attributes."

    @utils.log
    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    @utils.log
    def temp_function(self):
        self.temp_function_wrapper = general_temp_function(self.attributes)

    @utils.log
    def process_description(self):
        self.description_data = json.dumps(self.description_data,
                                              ensure_ascii=False)

    @utils.log
    def insert_description(self):
        model_wrappers.DescriptionWrapper(self.temp_function_wrapper,
                                          self.description_data,
                                          self.username).save()
        # TODO: user, not username


class RequestAction:
    @utils.log
    def __init__(self, data):
        self.attributes = data["attributes"]
        self.temp_function_wrapper = None

    @utils.log
    def check_validity(self):
        if not (set(self.attributes.keys()) == set(ATTRIBUTES)):
            raise "Missing attribute(s) / Too many attributes."

    @utils.log
    def process_attributes(self):
        self.attributes = general_process_attributes(self.attributes)

    @utils.log
    def temp_function(self):
        self.temp_function_wrapper = general_temp_function(self.attributes)

    @utils.log
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

    @utils.log
    def dictionaries_filtering(self):
        func_wrapper = self.temp_function_wrapper
        func_set = self.filtered_function_set
        temp_func_itypes_dict = Counter(func_wrapper.itypes)
        func_set = dict_filter(func_set, extract_itypes_list,
                                        temp_func_itypes_dict)
        self.filtered_function_set = func_set

    @utils.log
    def matching_grade_filtering(self):
        self.matching_funcs = []
        temp_func_blocks = \
            generate_temp_func_blocks(self.temp_function_wrapper,
                                    self.temp_function_wrapper.dist_from_root)

        temp_func_graph = graph.Graph(temp_func_blocks,
                                      self.temp_function_wrapper.edges)

        for func in self.filtered_function_set:
            second_graph_edges = json.loads(func.graph.edges)
            second_func_blocks = generate_db_func_blocks(func)
            second_graph = graph.Graph(second_func_blocks, second_graph_edges)
            grade = GraphSimilarity(temp_func_graph, second_graph).ratio()
            # print str(func) + ": " + str(grade)
            if (grade >= MATCHING_THRESHOLD):
                self.matching_funcs.append((func, grade))

    @utils.log
    def get_descriptions(self):
        descriptions = []
        exe_names = ""
        print self.matching_funcs
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
                                     "created_by": desc.user.user_name,
                                     "data": desc_data,
                                     "exe_names": exe_names})
        return descriptions


@utils.log
def general_process_attributes(attributes):
    pro_attrs = {}
    pro_attrs["func_signature"] = attributes["func_signature"]
    pro_attrs["func_name"] = attributes["func_name"]
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
    pro_attrs["dist_from_root"] = graph["dist_from_root"]                                     
    pro_attrs["num_of_blocks"] = len(block_bounds)
    pro_attrs["num_of_edges"] = len(pro_attrs["edges"])

    return pro_attrs


@utils.log
def general_temp_function(attributes):
    return model_wrappers.FunctionWrapper(attributes)


@utils.log
def extract_strings_list(function):
    block_set = function.graph.block_set.all()
    strings = []
    for block in block_set:
        strings.append(instruction.string.value for instruction in block.instruction_set.exclude(string=None)) 
    return strings

@utils.log
def extract_calls_list(function):
    block_set = function.graph.block_set.all()
    calls = []
    for block in block_set:
        calls.append(instruction.call.name for instruction in block.instruction_set.exclude(call=None)) 
    return calls

@utils.log
def extract_itypes_list(function):
    block_set = function.graph.block_set.all()
    itypes = []
    for block in block_set:
        for instruction in block.instruction_set.all():
            itypes.append(instruction.itype)
    return itypes


@utils.log
def dict_filter(func_set, list_extraction_function, ref_dict):
    filtered_functions = []
    for func in func_set:
        func_dict = Counter(list_extraction_function(func))
        grade = DictionarySimilarity(func_dict, ref_dict).ratio()
        if (grade >= FILTERING_THRESHOLD):
            filtered_functions.append(func)
    return filtered_functions


@utils.log
def generate_temp_func_blocks(function_wrapper, dist_from_root):
    
    imms = []
    strings = []
    calls = []
    blocks = []
    
    for block_id in range(len(function_wrapper.blocks_bounds)): 
        start_offset = function_wrapper.blocks_bounds[block_id][0]
        end_offset = function_wrapper.blocks_bounds[block_id][1] + 1
      
        for offset in range(start_offset, end_offset):
            str_offset = str(offset)
            if str_offset in function_wrapper.immediates:
                imms.append(function_wrapper.immediates[str_offset])
  
            if str_offset in function_wrapper.strings:
                strings.append(function_wrapper.strings[str_offset])

            if str_offset in function_wrapper.calls:
                calls.append(function_wrapper.calls[str_offset])
        
        itypes = function_wrapper.itypes[start_offset: end_offset]
        
        blocks.append(graph.Block(itypes, strings, calls, imms, 
                                  function_wrapper.dist_from_root[str(block_id)]))
        imms = []
        strings = []
        calls = []
    
    return blocks
    

@utils.log
def generate_db_func_blocks(function):

    block_set = function.graph.block_set.all()
    blocks = []

    for block in block_set:
        itypes = [instruction.itype for instruction in block.instruction_set.all()]
        strings = [instruction.string.value for instruction in block.instruction_set.exclude(string=None)]
        calls = [instruction.call.name for instruction in block.instruction_set.exclude(call=None)]   
        imms =  [instruction.immediate for instruction in block.instruction_set.exclude(immediate=None)]  
        blocks.append(graph.Block(itypes, strings, calls, imms, block.dist_from_root))
    
    return blocks
