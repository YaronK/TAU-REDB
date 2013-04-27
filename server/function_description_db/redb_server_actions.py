import redb_model_wrappers
from function_description_db.models import Function

MAX_NUM_INSNS_DEVIATION = 0.15
MAX_NUM_BLOCKS_DEVIATION = 0.15
MAX_NUM_EDGES_DEVIATION = 0.15
MAX_NUM_STRINGS_DEVIATION = 0.15
MAX_NUM_LIBCALLS_DEVIATION = 0.15

ATTRIBUTES = ["first_addr",
              "func_signature",
              "num_of_args",
              "num_of_vars",
              "itypes",
              "strings",
              "library_calls",
              "exe_signature",
              "graph"]

DESCRIPTION_DATA = ["data",
                    "user_name",
                    "password_hash"]


class SubmitAction:
    def __init__(self, attributes, description_data):
        self.attributes = attributes
        self.description_data = description_data
        self.temp_function_wrapper = None
        self.temp_description_wrapper = None
        self.filter_functions_set = None

    def check_validity(self):
        if not all_attributes_exist(self.attributes):
            return False
        if not all_description_items_exist(self.description_data):
            return False
        return True

    def generate_temp_function(self):
        self.temp_function_wrapper = generate_temp_function(self.attributes)
        if self.temp_function_wrapper == None:
            return False
        return True

    def generate_temp_description(self):
        self.temp_description_wrapper = \
            generate_temp_description(self.temp_function_wrapper,
                                 self.description_data)
        if self.temp_description_wrapper == None:
            return False
        return True

    def insert_description(self):
        try:
            existing_descriptions = \
                self.temp_description_wrapper.find_existing()
            if (len(existing_descriptions) > 0):
                print "REDB: Description already exists"
            else:
                self.temp_description_wrapper.save()
            return True
        except:
            return False


class RequestAction:
    def __init__(self, attributes):
        self.attributes = attributes
        self.temp_function_wrapper = None

    def check_validity(self):
        if not all_attributes_exist(self.attributes):
            return False

    def generate_temp_function(self):
        self.temp_function_wrapper = generate_temp_function(self.attributes)
        if self.temp_function_wrapper == None:
            return False
        return True

    def filter_functions(self):
        function = self.temp_function_wrapper.function
        func_set = Function.objects.all()
        print "num of functions before filtering:" + len(func_set)

        insns_num = function.instruction_set.count()
        func_set =\
            func_set.filter(insctruction_set__count__range=  # @IgnorePep8
                            (insns_num * (1 - MAX_NUM_INSNS_DEVIATION),
                             insns_num * (1 + MAX_NUM_INSNS_DEVIATION)))
        print "after num_of_insns range filter:" + len(func_set)

        num_of_blocks = function.graph.num_of_blocks
        func_set = \
            func_set.filter(graph__num_of_blocks__range=  # @IgnorePep8
                            (num_of_blocks * (1 - MAX_NUM_BLOCKS_DEVIATION),
                            num_of_blocks * (1 + MAX_NUM_BLOCKS_DEVIATION)))
        print "after graph_num_of_blocks range filter:" + len(func_set)

        num_of_edges = function.graph.num_of_edges
        func_set = \
            func_set.filter(graph__num_of_edges__range=  # @IgnorePep8
                            (num_of_edges * (1 - MAX_NUM_EDGES_DEVIATION),
                            num_of_edges * (1 + MAX_NUM_EDGES_DEVIATION)))
        print "after graph_num_of_edges range filter:" + len(func_set)

        num_of_strings = function.string_set.count()
        func_set = \
            func_set.filter(string_set__count__range=  # @IgnorePep8
                            (num_of_strings * (1 - MAX_NUM_STRINGS_DEVIATION),
                            num_of_strings * (1 + MAX_NUM_STRINGS_DEVIATION)))
        print "after graph_num_of_strings range filter:" + len(func_set)

        num_of_libcalls = function.librarycall_set.count()
        func_set = \
            func_set.filter(librarycall_set__count__range=  # @IgnorePep8
                            (num_of_libcalls *
                            (1 - MAX_NUM_LIBCALLS_DEVIATION),
                            num_of_libcalls *
                            (1 + MAX_NUM_LIBCALLS_DEVIATION)))
        print "after graph_num_of_library_calls range filter:" + len(func_set)

        self.filter_functions_set = func_set

    def get_descriptions(self):
        pass


def all_attributes_exist(attributes):
    for attribute_name in ATTRIBUTES:
        if attribute_name not in attributes:
            print ("REDB: required attribute" + attribute_name +
                   "was not found")
            return False


def all_description_items_exist(description_data):
    for description_item in DESCRIPTION_DATA:
        if description_item not in description_data:
            print ("REDB: required description_item" + description_item +
                   "was not found")
            return False


def generate_temp_function(attributes):
    try:
        return redb_model_wrappers.FunctionWrapper(attributes)
    except:
        print ("REDB: an error occurred while generating " +
               "temporary function.")
        return None


def generate_temp_description(function, description_data):
    try:
        return redb_model_wrappers.DescriptionWrapper(function,
                                                      description_data)
    except:
        print ("REDB: an error occurred while generating " +
               "temporary description.")
        return None

"""
    filtered_functions = []

    function_grade_pairs = []
    for filtered_function in filtered_functions:
        matching_grade = redb_similarity_grading.similarity_grading().\
            matching_grade(filtered_function, second_function)
        if matching_grade >= redb_similarity_grading.MATCHING_THRESHOLD:
            pair = (filtered_function, matching_grade)
            function_grade_pairs.append(pair)

    sorted_functions = sorted(function_grade_pairs, key=lambda func: func[1])
    sorted_functions.reverse()

    suggested_descriptions = []

    for func, grade in sorted_functions:
        if len(suggested_descriptions) == num_req_descs:
            break
        fitting_descriptions = Description.objects.filter(function=func)
        for desc in fitting_descriptions:
            func_name_and_cmts = json.loads(desc.func_name_and_cmts,
                                            object_hook=_decode_dict)
            suggested_description = \
                SuggestedDecsription(func_name_and_cmts=func_name_and_cmts,
                                     matching_grade=grade,
                                     can_be_embedded=(func.ins_num ==
                                                      second_function.ins_num),
                                     date=desc.date)

            suggested_description_dict = suggested_description.to_dict()
            suggested_descriptions.append(suggested_description_dict)
            if len(suggested_descriptions) == num_req_descs:
                break
"""
