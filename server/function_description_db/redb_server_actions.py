import redb_model_wrappers
from models import (Function, Description, String, LibraryCall,
                    Executable, Instruction, User, Graph)

MAX_NUM_INSNS_DEVIATION = 0.15

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
        insns_num = function.num_of_insns
        func_set = Function.objects.all()

        func_set = func_set.filter(num_of_insns__range=  # @IgnorePep8
                                   (insns_num * (1 - MAX_NUM_INSNS_DEVIATION),
                                    insns_num * (1 + MAX_NUM_INSNS_DEVIATION)))

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
