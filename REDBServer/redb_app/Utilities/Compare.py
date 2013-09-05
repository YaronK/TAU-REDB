from redb_app.models import Function, String, Call, Instruction, Executable, Graph, Description
import xlwt
import redb_app.utils
from redb_app.heuristics import GraphSimilarity
import numpy as np
import matplotlib.pyplot as plt
from difflib import SequenceMatcher
import heapq
import json

NAME_SIMILARITY_THRESHOLD = 0.8


def get_function_graph_by_id(func_id):
    return Function.objects.get(id=func_id).graph_set.all()[0].get_data()


def generate_matching_grade_by_id(a_id, b_id, test=False):
    a_graph = get_function_graph_by_id(a_id)
    b_graph = get_function_graph_by_id(b_id)
    return GraphSimilarity(a_graph, b_graph).ratio(test=test)


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
    return intersected_func_names


def get_functions_with_similar_name(func_name, function_set):
    return filter(lambda f: SequenceMatcher(a=f.func_name,
                                            b=func_name).ratio() >=
                  NAME_SIMILARITY_THRESHOLD, function_set)


def extract_block_attrs_similarities(func_set_1, func_set_2, path):
    similarities = {}
    for func_1 in func_set_1:
        graph_1 = get_function_graph_by_id(func_1.id)
        for func_2 in func_set_2:
            graph_2 = get_function_graph_by_id(func_2.id)

            graph_sim = GraphSimilarity(graph_1, graph_2)
            block_sim = graph_sim.calc_block_similarities(True)
            similarities[str((func_1.id, func_2.id))] = block_sim

    json.dump(similarities, open(path, 'w'))


def calc_weighted_block_similarities(func1_id, func2_id,
                                     block_attrs_similarities, weights_list):
    bs_attr = block_attrs_similarities[str((func1_id, func2_id))]
    block_similarities_weighted = []
    [itypes_weight, strings_weight, calls_weight, imms_weight] = weights_list
    for block in bs_attr:
        block_similarities_weighted.append(itypes_weight * block[0] +
                                           strings_weight * block[1] +
                                           calls_weight * block[2] +
                                           imms_weight * block[3])
    return block_similarities_weighted


def get_all_weights_combibation():
    def frange(x, y, jump):
        while x < y:
            yield x
            x += jump

    all_weights_combination = []
    for i in frange(0, 1, 0.1):
        for j in frange(0, 1 - i, 0.1):
            for k in frange(0, 1 - i - j, 0.1):
                l = 1 - i - j - k
                all_weights_combination.append([i, j, k, l])
    return all_weights_combination


def tune_to_optimal_weights(func_set_1, func_set_2, path,
                            names_similarity_threshold):
    block_attrs_similarities = \
         json.load(open(path), object_hook=redb_app.utils._decode_dict)
    all_weights_combination = get_all_weights_combibation()
    cur_similar_grade = 0
    cur_non_similar_grade = 0
    best_delta = 0
    for weights_list in all_weights_combination:
        for func1 in func_set_1:
            for func2 in func_set_2:
                block_similarities = \
                     calc_weighted_block_similarities(func1.id,
                                                      func2.id,
                                                      block_attrs_similarities,
                                                      weights_list)

                grade = generate_matching_grade_by_id(func1.id, func2.id,
                                                      test=block_similarities)
                if SequenceMatcher(a=func1.func_name, b=func1.func_name).ratio() == names_similarity_threshold:
                    cur_similar_grade += grade
                else:
                    cur_non_similar_grade += grade
        if cur_similar_grade - cur_non_similar_grade > best_delta:
            best_delta = cur_similar_grade - cur_non_similar_grade
            optimal_weight = weights_list
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
