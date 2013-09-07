from redb_app.models import Function, String, Call, Instruction, Executable, Graph, Description
import xlwt
import redb_app.utils
from redb_app.heuristics import GraphSimilarity
import numpy as np
import matplotlib.pyplot as plt
from difflib import SequenceMatcher
import heapq
import json
import pylab as pl
import os
import redb_app.constants as constants
NAME_SIMILARITY_THRESHOLD = 0.8
import copy


def get_function_graph_by_id(func_id):
    return Function.objects.get(id=func_id).graph_set.all()[0].get_data()


def generate_matching_grade_by_id(a_id, b_id, weights=None):
    a_graph = get_function_graph_by_id(a_id)
    b_graph = get_function_graph_by_id(b_id)
    return GraphSimilarity(a_graph, b_graph).ratio(weights=weights)


EXCLUDED_ON_EXE_COMPARISON = ["unknown", "sub_"]


def get_intersecting_func_names(exe_name1, exe_name2):
    exe1_funcs = Function.objects.filter(exe_name=exe_name1)
    exe2_funcs = Function.objects.filter(exe_name=exe_name2)
    exe1_func_names = [func.func_name for func in exe1_funcs]
    exe2_func_names = [func.func_name for func in exe2_funcs]
    intersected_func_names = set(exe1_func_names) & set(exe2_func_names)
    for excluded in EXCLUDED_ON_EXE_COMPARISON:
        intersected_func_names = filter(lambda n: excluded not in n,
                                        intersected_func_names)
    exe1 = []
    exe2 = []
    for n in intersected_func_names:
        exe1.append(exe1_funcs.get(func_name=n))
        exe2.append(exe2_funcs.get(func_name=n))
    return (exe1, exe2)


def get_functions_with_similar_name(func_name, function_set):
    return filter(lambda f: SequenceMatcher(a=f.func_name,
                                            b=func_name).ratio() >=
                  NAME_SIMILARITY_THRESHOLD, function_set)


def extract_block_attrs_similarities(func_set_1, func_set_2, dir_path):
    similarities = {}
    num_of_comparisons = len(func_set_1) * len(func_set_2)
    counter = 0
    for func_1 in func_set_1:
        graph_1 = get_function_graph_by_id(func_1.id)
        for func_2 in func_set_2:
            file_path = os.path.join(dir_path, str(func_1.id) + "_" + str(func_2.id))
            if os.path.exists(file_path):
                continue
            graph_2 = get_function_graph_by_id(func_2.id)

            graph_sim = GraphSimilarity(graph_1, graph_2)
            block_sim = graph_sim.calc_block_similarities(test=True)
            # similarities[str((func_1.id, func_2.id))] = block_sim
            counter += 1
            print str(counter) + "/" + str(num_of_comparisons)

            json.dump(block_sim, open(file_path, 'w'))


def calc_weighted_block_similarities(block_attrs_similarities, weights):

    block_similarities_weighted = []
    for block in block_attrs_similarities:
        itypes_similarity = block[2][0]
        strings_similarity = block[2][1]
        calls_similarity = block[2][2]
        imms_similarity = block[2][3]

        if itypes_similarity is None:
            itypes_similarity = 0
            itypes_weight = 0
        else:
            itypes_weight = weights["itypes"]

        if strings_similarity is None:
            strings_similarity = 0
            strings_weight = 0
        else:
            strings_weight = weights["strings"]

        if calls_similarity is None:
            calls_similarity = 0
            calls_weight = 0
        else:
            calls_weight = weights["calls"]

        if imms_similarity is None:
            imms_similarity = 0
            imms_weight = 0
        else:
            imms_weight = weights["imms"]

        sum_weights = (itypes_weight + strings_weight +
                       calls_weight + imms_weight)

        itypes_weight = itypes_weight / float(sum_weights)
        strings_weight = strings_weight / float(sum_weights)
        calls_weight = calls_weight / float(sum_weights)
        imms_weight = imms_weight / float(sum_weights)
        # print [itypes_weight, strings_weight, calls_weight, imms_weight]
        block_similarities_weighted.append((block[0],
                                           block[1],
                                           itypes_weight * itypes_similarity +
                                           strings_weight * strings_similarity +
                                           calls_weight * calls_similarity +
                                           imms_weight * imms_similarity))
    return block_similarities_weighted


def get_all_weights_combibation():
    all_weights_combination = []
    max_weight = 10
    for i in range(5, max_weight, 1):
        for j in range(0, max_weight - i, 1):
            for k in range(0, max_weight - i - j, 1):
                l = max_weight - i - j - k
                # if l == 0:
                #   continue
                all_weights_combination.append([i, j, k, l])
    return all_weights_combination


def get_grade_given_weights(func1, func2, weights):
    grade = generate_matching_grade_by_id(func1.id, func2.id, weights=weights)
    return grade


def test_weight(weight_list, func_set_1, func_set_2,
                 names_similarity_threshold):

    weights = {}
    weights["itypes"] = weight_list[0]
    weights["strings"] = weight_list[1]
    weights["calls"] = weight_list[2]
    weights["imms"] = weight_list[3]

    step = 0.02
    should_be_equal_grades = []
    should_be_different_grades = []

    print "testing weight: " + str(weights)
    for func1 in func_set_1:
        for func2 in func_set_2:
            grade = get_grade_given_weights(func1, func2, weights)
            name_similarity = SequenceMatcher(a=func1.func_name,
                                              b=func2.func_name).ratio()
            if (name_similarity >= names_similarity_threshold):
                should_be_equal_grades.append(grade)
            else:
                should_be_different_grades.append(grade)

    min_max_false_ratio = 2.0  # worst ratio
    min_max_false_ratio_threshold = 0
    min_max_false_ratio_false_pos = 0
    min_max_false_ratio_false_neg = 0
    for threshold in pl.frange(0.01, 1, step):

        pos = (len(filter(lambda x: x > threshold, should_be_different_grades)) +
               len(filter(lambda x: x > threshold, should_be_equal_grades)))

        neg = (len(filter(lambda x: x < threshold, should_be_different_grades)) +
               len(filter(lambda x: x < threshold, should_be_equal_grades)))

        false_pos = len(filter(lambda x: x > threshold, should_be_different_grades))

        false_neg = len(filter(lambda x: x < threshold, should_be_equal_grades))

        false_pos_ratio = false_pos / float(pos) if float(pos) != 0 else 1.0
        false_neg_ratio = false_neg / float(neg) if float(neg) != 0 else 1.0

        max_false_ratio = max(false_pos_ratio, false_neg_ratio)

        if min_max_false_ratio >= max_false_ratio:
            min_max_false_ratio = max_false_ratio
            min_max_false_ratio_false_pos = false_pos_ratio
            min_max_false_ratio_false_neg = false_neg_ratio
            min_max_false_ratio_threshold = threshold
    print ("false_pos_ratio: " + str(min_max_false_ratio_false_pos) +
           ", false_neg_ratio: " + str(min_max_false_ratio_false_neg) +
           ", min_max: " + str(min_max_false_ratio) +
           ", threshold: " + str(min_max_false_ratio_threshold))
    #print [min_max_false_ratio, min_max_false_ratio_threshold]
    return min_max_false_ratio, min_max_false_ratio_threshold


def tune_to_optimal_weights(func_set_1, func_set_2, names_similarity_threshold):

    all_weights_combination = get_all_weights_combibation()

    best_weights = []
    min_max_false_ratio_total = 2.0
    min_max_false_ratio_threshold_total = 0

    for weight_list in all_weights_combination:

        (min_max_false_ratio, min_max_false_ratio_threshold) = \
            test_weight(weight_list, func_set_1, func_set_2,
                        names_similarity_threshold)

        if min_max_false_ratio_total >= min_max_false_ratio:
            min_max_false_ratio_total = min_max_false_ratio
            min_max_false_ratio_threshold_total = min_max_false_ratio_threshold
            best_weights = weight_list
            print "best weights: " + str(best_weights)

    print (min_max_false_ratio_total,
           min_max_false_ratio_threshold_total,
           best_weights)


def compare_function_sets(func_set_1, func_set_2):

    gmgbi = generate_matching_grade_by_id

    res_matrix = [[gmgbi(func1.id, func2.id) for func1 in func_set_1]
                  for func2 in func_set_2]

    return res_matrix


def compare_function_set_excel(path, func_set_1, func_set_2):
    book = xlwt.Workbook(encoding="utf-8")
    sheet1 = book.add_sheet("Sheet1")
    xlwt.Alignment.HORZ_CENTER
    xlwt.Alignment.VERT_CENTER
    res_mat = compare_function_sets(func_set_1, func_set_2)
    rows = len(res_mat)
    cols = len(res_mat[0])
    for i in range(1, rows + 1):
        for j in range(1, cols + 1):
            sheet1.write(i, j, res_mat[i][j])

    for i in range(rows):
        sheet1.write(i + 1, 0, func_set_1[i].func_name)
    for j in range(cols):
        sheet1.write(0, j + 1, func_set_2[j].func_name)

    book.save(path)


def compare_function_sets_heat_map(path, func_set_1, func_set_2):
    res_mat = compare_function_sets(func_set_1, func_set_2)
    func_set_names_1 = [func.func_name for func in func_set_1]
    func_set_names_2 = [func.func_name for func in func_set_2]
    data = np.array(res_mat)
    fig, ax = plt.subplots()
    heatmap = ax.pcolor(data, cmap=plt.cm.Blues)  # @UndefinedVariable
    ax.set_xticks(np.arange(data.shape[0]) + 0.5, minor=False)
    ax.set_yticks(np.arange(data.shape[1]) + 0.5, minor=False)
    ax.invert_yaxis()
    ax.xaxis.tick_top()
    ax.set_yticklabels(func_set_names_1, minor=False)
    ax.set_xticklabels(func_set_names_2, minor=False)
    plt.xticks(rotation=90)
    plt.rcParams.update({'font.size': 4})
    # fig.tight_layout()
    plt.savefig(path, bbox_inches='tight', dpi=100)
    plt.show()


def get_top_similarities_for_single_function(num_of_tops, func, func_set):
    similarity_res = []
    for compared_func in func_set:
        print (compared_func.id, func.id)
        similarity_grade = generate_matching_grade_by_id(compared_func.id, func.id)
        similarity_res.append((similarity_grade, compared_func.func_name))

    return heapq.nlargest(num_of_tops, similarity_res)


def get_top_similarities_for_all_functions(func_set_1, func_set_2, num_of_tops, path):
    f = open(path, 'w')
    delimeter_line = \
         "\n###############################################################\n"
    for func in func_set_1:
        top_similars = get_top_similarities_for_single_function(num_of_tops, func, func_set_2)
        f.write("%s: top similars\n" % str((func.func_name, func.exe_name)))
        for item in top_similars:
            f.write("%s, %.3f\n" % (item[1], item[0]))
        expected_similarities = \
            get_functions_with_similar_name(func.func_name, func_set_2)
        f.write("Expected:\n")
        for func in expected_similarities:
            f.write(str((func.func_name, func.exe_name)) + ', ')
        f.write(delimeter_line)
    f.close()


def get_bounds(mean, deviation):
    return mean * (1 - deviation), mean * (1 + deviation)

con_db = constants.db_filter


def insns_num_filter(func, func_set,
                     deviation=con_db.MAX_NUM_INSNS_DEVIATION):
    insns_num = func.num_of_insns
    lower_bound, upper_bound = get_bounds(insns_num, deviation)
    func_set = func_set.filter(num_of_insns__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def blocks_num_filter(func, func_set,
                      deviation=con_db.MAX_NUM_BLOCKS_DEVIATION):
    num_of_blocks = func.graph_set.all()[0].num_of_blocks
    lower_bound, upper_bound = get_bounds(num_of_blocks, deviation)
    func_set = func_set.filter(graph__num_of_blocks__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def edges_num_filter(func, func_set,
                     deviation=con_db.MAX_NUM_EDGES_DEVIATION):
    num_of_edges = func.graph_set.all()[0].num_of_edges
    lower_bound, upper_bound = get_bounds(num_of_edges, deviation)
    func_set = func_set.filter(graph__num_of_edges__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def vars_size_filter(func, func_set,
                     deviation=con_db.MAX_VARS_SIZE_DEVIATION):
    vars_size = func.vars_size
    lower_bound, upper_bound = get_bounds(vars_size, deviation)
    func_set = func_set.filter(vars_size__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def args_size_filter(func, func_set,
                     deviation=con_db.MAX_ARGS_SIZE_DEVIATION):
    args_size = func.args_size
    lower_bound, upper_bound = get_bounds(args_size, deviation)
    func_set = func_set.filter(args_size__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def regs_size_filter(func, func_set,
                     deviation=con_db.MAX_REGS_SIZE_DEVIATION):
    regs_size = func.regs_size
    lower_bound, upper_bound = get_bounds(regs_size, deviation)
    func_set = func_set.filter(regs_size__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def calls_num_filter(func, func_set,
                     deviation=con_db.MAX_NUM_CALLS_DEVIATION):
    num_of_calls = func.num_of_calls
    lower_bound, upper_bound = get_bounds(num_of_calls, deviation)
    func_set = func_set.filter(num_of_calls__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def strings_num_filter(func, func_set,
                       deviation=con_db.MAX_NUM_STRINGS_DEVIATION):
    num_of_strings = func.num_of_strings
    lower_bound, upper_bound = get_bounds(num_of_strings, deviation)
    func_set = func_set.filter(num_of_strings__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def imms_num_filter(func, func_set,
                    deviation=con_db.MAX_NUM_IMMS_DEVIATION):
    num_of_imms = func.num_of_imms
    lower_bound, upper_bound = get_bounds(num_of_imms, deviation)
    func_set = func_set.filter(num_of_imms__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def before_after(my_func_index, filter_func, deviation=None):
    my_func = Function.objects.all()[my_func_index]
    print "Before: " + str(len(Function.objects.all()))
    if deviation != None:
        after = len(filter_func(my_func, Function.objects.all(), deviation))
    else:
        after = len(filter_func(my_func, Function.objects.all()))
    print "After: " + str(after)


def filter_stage(func, func_set, filter_func, deviation):
    before = len(func_set)
    print "before " + filter_func.__name__ + str(before)

    if deviation != None:
        func_set = filter_func(func, func_set, deviation)
    else:
        func_set = filter_func(func, func_set)

    after = len(func_set)
    print "after " + filter_func.__name__ + str(after)

    diff = before - after
    print "diff " + filter_func.__name__ + str(diff)
    return (diff, func_set)


def filter_several_stages(func_set, filter_functions, deviation=None):
    diffs = []
    for func in func_set:
        func_set_copy = copy.deepcopy(func_set)
        for filter_function in filter_functions:
            diff, func_set_copy = filter_stage(func, func_set_copy, filter_function,
                                          deviation)
            if (filter_functions.index(filter_function) ==
                len(filter_functions) - 1):  # last filter
                diffs.append(diff)

    return np.mean(diffs)



LIBC_FUNC_NAMES = ["inet_ntoa", "inet_aton" , "inet_addr", "inet_ntop",
                   "inet_pton", "execve", "accept", "alarm", "alphasort",
                   "asctime", "atol", "bind", "bsearch", "calloc", "chdir",
                   "chmod", "chown", "chroot", "clock", "clock_settime",
                   "clock_gettime", "connect", "cos", "difftime", "dirname",
                   "div", "exit", "exp", "fseek", "getcwd",
                   ]

