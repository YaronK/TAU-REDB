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
from lib2to3.fixer_util import String
NAME_SIMILARITY_THRESHOLD = 0.8


def get_function_graph_by_id(func_id):
    return Function.objects.get(id=func_id).graph_set.all()[0].get_data()


def generate_matching_grade_by_id(a_id, b_id, block_similarity_tuples=None,
                                  weights=None):
    a_graph = get_function_graph_by_id(a_id)
    b_graph = get_function_graph_by_id(b_id)
    return GraphSimilarity(a_graph, b_graph).ratio(block_similarity_tuples=block_similarity_tuples,
                                                   weights=weights)


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
            graph_2 = get_function_graph_by_id(func_2.id)

            graph_sim = GraphSimilarity(graph_1, graph_2)
            block_sim = graph_sim.calc_block_similarities(test=True)
            # similarities[str((func_1.id, func_2.id))] = block_sim
            counter += 1
            print str(counter) + "/" + str(num_of_comparisons)
            file_path = os.path.join(dir_path, str(func_1.id) + "_" + str(func_2.id))
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
    for i in range(int(max_weight * 1 / 2), max_weight, 1):
        for j in range(0, max_weight - i, 1):
            for k in range(0, max_weight - i - j, 1):
                l = max_weight - i - j - k
                all_weights_combination.append([i, j, k, l])
    return all_weights_combination


def tune_to_optimal_weights(func_set_1, func_set_2, dir_path,
                            names_similarity_threshold):

    all_weights_combination = get_all_weights_combibation()
    cur_similar_grade = 0
    similar_name_counter = 0
    cur_non_similar_grade = 0
    non_similar_name_counter = 0
    best_delta = float("-infinity")
    for weight_list in all_weights_combination:
        weights = {}
        weights["itypes"] = weight_list[0]
        weights["strings"] = weight_list[1]
        weights["calls"] = weight_list[2]
        weights["imms"] = weight_list[3]

        print "testing weight: " + str(weight_list)
        for func1 in func_set_1:
            for func2 in func_set_2:
                # print str((func1.id, func2.id))
                file_path = os.path.join(dir_path, str(func1.id) + "_" + str(func2.id))
                block_attrs_similarities = json.load(open(file_path))
                block_similarities = \
                     calc_weighted_block_similarities(block_attrs_similarities,
                                                      weights)

                grade = generate_matching_grade_by_id(func1.id, func2.id,
                                                      block_similarity_tuples=block_similarities,
                                                      weights=weights)
                name_similarity = SequenceMatcher(a=func1.func_name,
                                                  b=func2.func_name).ratio()
                if (name_similarity >= names_similarity_threshold):
                    cur_similar_grade += grade
                    similar_name_counter += 1
                else:
                    cur_non_similar_grade += grade
                    non_similar_name_counter += 1
        cur_delta = (cur_similar_grade / float(similar_name_counter) -
                     cur_non_similar_grade / float(non_similar_name_counter))
        if cur_delta >= best_delta:
            print "old best delta: " + str(best_delta)
            best_delta = cur_delta
            print "new best delta: " + str(best_delta)
            print "best weight: " + str(weight_list)
            optimal_weight = weight_list
        cur_non_similar_grade = 0
        cur_similar_grade = 0
        similar_name_counter = 0
        non_similar_name_counter = 0
    return optimal_weight


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


# TODO: separate comparison and extraction
