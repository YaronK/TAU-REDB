class SubmitAction:
    def __init__(self, attributes, description):
        self.attributes = attributes
        self.description = description

    def check_validity(self):
        # TODO
        pass

    def generate_temp_function(self):
        pass

    def generate_description(self):
        pass

    def insert_description(self):
        pass


class RequestAction:
    def __init__(self, attributes):
        self.attributes = attributes

    def check_validity(self):
        # TODO
        pass

    def generate_temp_function(self):
        pass

    def filter_functions(self):
        pass

    def get_descriptions(self):
        pass

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
