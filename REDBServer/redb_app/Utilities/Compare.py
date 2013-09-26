from redb_app.models import Function, String, Call, Instruction, Executable, Graph, Description
import xlwt
from redb_app.heuristics import GraphSimilarity
import numpy as np
import matplotlib.pyplot as plt
from difflib import SequenceMatcher
import heapq
import json
import pylab as pl
import random
import os
import redb_app.constants as constants
import time
NAME_SIMILARITY_THRESHOLD = 0.8
import copy
from redb_app.utils import test_log
import scipy.cluster.hierarchy as sch  # @UnresolvedImport
import pylab
from textwrap import wrap
import math


def get_function_graph_by_id(func_id):
    return Function.objects.get(id=func_id).graph_set.all()[0].get_data()


def get_function_name_by_id(func_id):
    return Function.objects.get(id=func_id).func_name


def generate_matching_grade_by_id(a_id, b_id, test_dict=None):
    a_graph = get_function_graph_by_id(a_id)
    b_graph = get_function_graph_by_id(b_id)
    log_decisions = test_dict and "log_decisions" in test_dict
    if log_decisions:
        a_name = get_function_name_by_id(a_id)
        b_name = get_function_name_by_id(b_id)
        test_log("start: " +
                 a_name + " (" + str(a_id) + "), " +
                 b_name + " (" + str(b_id) + ")")
    # print (a_id, b_id)
    similarity = GraphSimilarity(a_graph, b_graph).ratio(test_dict=test_dict)
    if log_decisions:
        test_log("finish: " +
                 a_name + " (" + str(a_id) + "), " +
                 b_name + " (" + str(b_id) + ")" + "\n")
    return similarity


EXCLUDED_ON_EXE_COMPARISON = ["unknown", "sub_", "lock"]


def get_intersecting_func_names(exe_name1, exe_name2):
    func_set = Function.objects.exclude(num_of_insns__range=(1, 4))
    exe1_funcs = func_set.filter(exe_name=exe_name1)
    exe2_funcs = func_set.filter(exe_name=exe_name2)
    exe1_func_names = [func.func_name for func in exe1_funcs]
    exe2_func_names = [func.func_name for func in exe2_funcs]
    intersected_func_names = set(exe1_func_names) & set(exe2_func_names)

    for excluded in EXCLUDED_ON_EXE_COMPARISON:
        intersected_func_names = filter(lambda n: excluded not in n,
                                        intersected_func_names)

    index_list = random.sample(range(len(intersected_func_names)), 300)
    intersected_func_names = [intersected_func_names[i] for i in index_list]
    """
    exe1 = []
    exe2 = []

    for name in intersected_func_names:
        exe1.append(exe1_funcs.get(func_name=name))
        exe2.append(exe2_funcs.get(func_name=name))
    """
    exe1 = exe1_funcs.filter(func_name__in=intersected_func_names)
    exe2 = exe2_funcs.filter(func_name__in=intersected_func_names)

    return (exe1, exe2)


def get_functions_with_similar_name(func_name, function_set):
    return filter(lambda f: SequenceMatcher(a=f.func_name,
                                            b=func_name).ratio() >=
                  NAME_SIMILARITY_THRESHOLD, function_set)


def compare_function_sets(func_set_1, func_set_2, test_dict=None, path=None):

    gmgbi = generate_matching_grade_by_id

    res_matrix = [[gmgbi(func1.id, func2.id, test_dict=test_dict)
                   for func1 in func_set_1] for func2 in func_set_2]

    names = []
    names.append([func.func_name for func in func_set_1])
    names.append([func.func_name for func in func_set_2])
    if path is not None:
        json.dump(res_matrix, open(path, 'w'))
        json.dump(names, open(path + "_names", 'w'))
    return res_matrix


def compare_function_sets_using_filtering(func_set_1, func_set_2, path_dump_res,
                                          path_res_no_filtering):
    names = []
    names.append([func.func_name for func in func_set_1])
    names.append([func.func_name for func in func_set_2])
    res_mat = [[0 for col in range(len(func_set_1))] for row in range(len(func_set_2))]
    no_filtering_res_mat = json.load(open(path_res_no_filtering))
    counter = 0
    for func1 in func_set_1:
        func_set = func_set_2
        func_set = insns_num_filter(func1, func_set, get_bounds_rough)
        func_set = edges_num_filter(func1, func_set, get_bounds_fine_tuning)
        func_set = blocks_num_filter(func1, func_set, get_bounds_fine_tuning)
        # func_set = vars_size_filter(func1, func_set)
        # func_set = args_size_filter(func1, func_set)
        # func_set = regs_size_filter(func1, func_set)
        func_set = calls_num_filter(func1, func_set, get_bounds_rough)
        func_set = imms_num_filter(func1, func_set, get_bounds_rough)
        func_set = strings_num_filter(func1, func_set, get_bounds_rough)
        print "no. of functions left after filtering: " + str(len(func_set))
        for func in func_set:
            col = names[0].index(func1.func_name)
            row = names[1].index(func.func_name)
            res_mat[row][col] = no_filtering_res_mat[row][col]
            counter += 1

    json.dump(res_mat, open(path_dump_res, 'w'))
    json.dump(names, open(path_dump_res + "_names", 'w'))
    print counter
    return res_mat


def get_optimal_threshold(func_set_1, func_set_2, test_dict=None):
    res_matrix = compare_function_sets(func_set_1, func_set_2,
                                       test_dict=test_dict)
    should_be_equal_grades = []
    should_be_different_grades = []

    for row in range(len(res_matrix)):
        for col in range(len(res_matrix[0])):
            grade = res_matrix[row][col]
            if row == col:
                should_be_equal_grades.append(grade)
            else:
                should_be_different_grades.append(grade)

    should_be_equal_mean = sum(should_be_equal_grades) / float(len(should_be_equal_grades))
    should_be_diff_mean = sum(should_be_different_grades) / float(len(should_be_different_grades))
    delta = should_be_equal_mean - should_be_diff_mean
    print "delta: " + str(delta)
    return delta


def compare_function_sets_excel(path, func_set_1, func_set_2):
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
    ax.invert_yaxis()

    ax.set_xticks(np.arange(data.shape[0]) + 0.5, minor=False)
    ax.set_yticks(np.arange(data.shape[1]) + 0.5, minor=False)

    ax.xaxis.tick_top()
    ax.set_yticklabels(func_set_names_1, minor=False)
    ax.set_xticklabels(func_set_names_2, minor=False)
    plt.xticks(rotation=90)
    plt.rcParams.update({'font.size': 4})
    # fig.tight_layout()

    plt.savefig(path, bbox_inches='tight', dpi=100)
    plt.show()


def compare_functions_clustering(path, func_set_1, func_set_2, res_path=None):
    if res_path is not None:
        res_mat = json.load(open(res_path))
        names = json.load(open(res_path + "_names", 'r'))
        names_1 = names[0]
        names_2 = names[1]
    else:
        res_mat = compare_function_sets(func_set_1, func_set_2)

    D = np.array(res_mat)

    fig = pylab.figure()
    Y = sch.linkage(D, method='centroid')

    Z = sch.dendrogram(Y, orientation='right', no_plot=True, no_labels=True)

    # Plot distance matrix.
    axmatrix = fig.add_axes([0.3, 0.1, 0.6, 0.8])
    index = Z['leaves']
    D = D[index, :]
    D = D[:, index]

    im = axmatrix.matshow(D, aspect='auto', origin='lower', cmap=pylab.cm.Blues)
    axmatrix.set_xticks(np.arange(D.shape[0]) + 0.5, minor=False)
    axmatrix.set_yticks(np.arange(D.shape[1]) + 0.5, minor=False)

    names_1 = [names_1[i] for i in index]
    names_2 = [names_2[i] for i in index]
    axmatrix.set_xticklabels(names_1, rotation=90, minor=False)
    axmatrix.set_yticklabels(names_2, minor=False)
    axmatrix.invert_yaxis()

    # Plot colorbar.
    axcolor = fig.add_axes([0.91, 0.1, 0.02, 0.8])
    pylab.colorbar(im, cax=axcolor)
    plt.rcParams.update({'font.size': 4})

    # Display and save figure.
    fig.show()
    fig.savefig(path)


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


def create_heat_map_from_matrix(path_matrix, path_save, xlabel, ylabel, title):
    matrix = json.load(open(path_matrix))
    arr = np.array(matrix)
    fig, ax = plt.subplots()
    heatmap = ax.pcolor(arr, cmap=pylab.cm.Blues)
    """
    axcolor = fig.add_axes([0.91, 0.1, 0.02, 0.8])
    ax.set_xticks(np.arange(arr.shape[0]) + 0.5, minor=False)
    ax.set_yticks(np.arange(arr.shape[1]) + 0.5, minor=False)
    labels = pl.frange(0, 1, 0.1)
    ax.set_yticklabels(labels, minor=False)
    ax.set_xticklabels(labels, minor=False)
    ax.set_ylabel(ylabel)
    ax.set_xlabel(xlabel)
    ax.set_title('\n'.join(wrap(title, 60)))
    pylab.colorbar(heatmap, cax=axcolor)
    """
    plt.show()
    plt.savefig(path_save)


def get_bounds_rough(mean):
    if mean == 0:
        delta = 6
    elif mean <= 10:
        delta = mean * 3
    elif mean <= 15:
        delta = mean * 2
    elif mean <= 20:
        delta = math.ceil(mean * 1.5)
    elif mean <= 60:
        delta = math.ceil(mean * 0.5)
    elif mean <= 100:
        delta = math.ceil(mean * 0.4)
    elif mean <= 200:
        delta = math.ceil(mean * 0.3)
    else:
        delta = math.ceil(mean * 0.2)
    lower_bound = mean - delta
    upper_bound = mean + delta
    # lower_bound =  math.floor(mean * (1 - deviation))
    # upper_bound = math.ceil(mean * (1 + deviation))
    return lower_bound, upper_bound


def get_bounds_fine_tuning(mean):
    if mean == 0:
        delta = 4
    else:
        delta = math.ceil(mean * 0.2)
    lower_bound = mean - delta
    upper_bound = mean + delta
    return lower_bound, upper_bound


con_db = constants.db_filter


def insns_num_filter(func, func_set, get_bounds_func,
                     deviation=con_db.MAX_NUM_INSNS_DEVIATION):
    insns_num = func.num_of_insns
    lower_bound, upper_bound = get_bounds_func(insns_num)
    func_set = func_set.filter(num_of_insns__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def blocks_num_filter(func, func_set, get_bounds_func,
                      deviation=con_db.MAX_NUM_BLOCKS_DEVIATION):
    num_of_blocks = func.graph_set.all()[0].num_of_blocks
    lower_bound, upper_bound = get_bounds_func(num_of_blocks)
    func_set = func_set.filter(graph__num_of_blocks__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def edges_num_filter(func, func_set, get_bounds_func,
                     deviation=con_db.MAX_NUM_EDGES_DEVIATION):
    num_of_edges = func.graph_set.all()[0].num_of_edges
    lower_bound, upper_bound = get_bounds_func(num_of_edges)
    func_set = func_set.filter(graph__num_of_edges__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def vars_size_filter(func, func_set, get_bounds_func,
                     deviation=con_db.MAX_VARS_SIZE_DEVIATION):
    vars_size = func.vars_size
    lower_bound, upper_bound = get_bounds_func(vars_size)
    func_set = func_set.filter(vars_size__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def args_size_filter(func, func_set, get_bounds_func,
                     deviation=con_db.MAX_ARGS_SIZE_DEVIATION):
    args_size = func.args_size
    lower_bound, upper_bound = get_bounds_func(args_size)
    func_set = func_set.filter(args_size__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def regs_size_filter(func, func_set, get_bounds_func,
                     deviation=con_db.MAX_REGS_SIZE_DEVIATION):
    regs_size = func.regs_size
    lower_bound, upper_bound = get_bounds_func(regs_size)
    func_set = func_set.filter(regs_size__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def calls_num_filter(func, func_set, get_bounds_func,
                     deviation=con_db.MAX_NUM_CALLS_DEVIATION):
    num_of_calls = func.num_of_calls
    lower_bound, upper_bound = get_bounds_func(num_of_calls)
    func_set = func_set.filter(num_of_calls__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def strings_num_filter(func, func_set, get_bounds_func,
                       deviation=con_db.MAX_NUM_STRINGS_DEVIATION):
    num_of_strings = func.num_of_strings
    lower_bound, upper_bound = get_bounds_func(num_of_strings)
    func_set = func_set.filter(num_of_strings__range=  # @IgnorePep8
                               (lower_bound, upper_bound))
    return func_set


def imms_num_filter(func, func_set, get_bounds_func,
                    deviation=con_db.MAX_NUM_IMMS_DEVIATION):
    num_of_imms = func.num_of_imms
    lower_bound, upper_bound = get_bounds_func(num_of_imms)
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


def filter_several_stages(func_set, filtered_func_set,
                          filter_functions, deviation=None):
    diffs = []
    for func in func_set:
        func_set_copy = copy.deepcopy(filtered_func_set)
        for filter_function in filter_functions:
            diff, func_set_copy = filter_stage(func, func_set_copy, filter_function,
                                          deviation)
            if (filter_functions.index(filter_function) ==
                len(filter_functions) - 1):  # last filter
                diffs.append(diff)

    return np.mean(diffs)


def optimal_block_sim_threshold_min_block_dist_similarity(exe_name_1,
                                                          exe_name_2,
                                                          num_of_funcs):
    func_set = Function.objects.exclude(graph__num_of_blocks=1)
    exe1, exe2 = get_intersecting_func_names(func_set, exe_name_1,
                                             exe_name_2)
    index_list = random.sample(range(len(exe1)), num_of_funcs)
    funcs1 = [exe1[i] for i in index_list];
    funcs2 = [exe2[i] for i in index_list];
    best_block_sim_threshold = 0
    best_min_block_dist_similarity = 0
    best_delta = float("-infinity")
    for block_sim_threshold in pl.frange(0, 0.8, 0.1):
        for min_block_dist_similarity in pl.frange(0.5, 0.8, 0.1):
            print ("current", block_sim_threshold, min_block_dist_similarity)
            print ("best", best_block_sim_threshold, best_min_block_dist_similarity)
            test_dict = {  # "log_decisions": True,
                         "block_similarity_threshold": block_sim_threshold,
                         "min_block_dist_similarity": min_block_dist_similarity,
                         "association_graph_max_size": 5000}
            delta = \
                get_optimal_threshold(funcs1, funcs2, test_dict=test_dict)

            if best_delta < delta:
                best_delta = delta
                print "best delta: " + str(best_delta)
                best_block_sim_threshold = block_sim_threshold
                best_min_block_dist_similarity = min_block_dist_similarity

    print ("best_delta: " +
           str(best_delta) +
           ", best_block_sim_threshold: " +
           str(best_block_sim_threshold) +
           ", best_min_block_dist_similarity: " +
           str(best_min_block_dist_similarity))


def distance(s1, s2):
    ratio = SequenceMatcher(None, s1, s2).ratio()
    return 1.0 - ratio


def timings(exe_name_1, exe_name_2, num_of_funcs):
    exe1, exe2 = get_intersecting_func_names(exe_name_1, exe_name_2)

    index_list = random.sample(range(len(exe1)), num_of_funcs)
    funcs1 = [exe1[i] for i in index_list]
    funcs2 = [exe2[i] for i in index_list]

    bst = []
    timing_dict = {}
    for block_sim_threshold in pl.frange(0, 0.8, 0.1):
        block_sim_threshold = round(block_sim_threshold, 1)
        mbds = []
        for min_block_dist_similarity in pl.frange(0, 0.8, 0.1):
            min_block_dist_similarity = round(min_block_dist_similarity, 1)
            test_dict = {  # "log_decisions": True,
                         "block_similarity_threshold": block_sim_threshold,
                         "min_block_dist_similarity": min_block_dist_similarity,
                         "association_graph_max_size": 5000}
            start = time.time()
            delta = get_optimal_threshold(funcs1, funcs2, test_dict=test_dict)
            elapsed = (time.time() - start)
            mbds.append(elapsed)
            print (block_sim_threshold, min_block_dist_similarity, elapsed)
            timing_dict[block_sim_threshold][min_block_dist_similarity] = (delta, elapsed)
            print elapsed
        bst.append(mbds)
    return timing_dict


def generate_historgram(xlabel, ylabel, res_path):
    res_mat = json.load(open(res_path))
    """
    for row in range(len(res_mat)):
        res_mat[row].pop(row)
    """
    res_mat = [[res_mat[row][row]] for row in range(len(res_mat))]
    res_list = reduce(lambda x, y: x + y, res_mat)
    res_arr = np.array(res_list)
    fig = plt.figure()
    x = res_arr
    hist, bins = np.histogram(x, bins=50)
    width = 0.7 * (bins[1] - bins[0])
    center = (bins[:-1] + bins[1:]) / 2
    plt.bar(center, hist, align='center', width=width)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.show()
    fig.savefig(res_path + "_histogram" + ".pdf")


