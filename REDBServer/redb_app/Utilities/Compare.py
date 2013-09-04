from redb_app import actions, utils
from redb_app.models import Function
import json
import xlwt
from redb_app.heuristics import GraphSimilarity
import numpy as np
import matplotlib.pyplot as plt
from difflib import SequenceMatcher
import heapq

NAME_SIMILARITY_THRESHOLD = 0.8


def generate_matching_grade(a_id, b_id):
    a_graph = Function.objects.get(id=a_id).graph_set.all()[0].get_data()
    b_graph = Function.objects.get(id=b_id).graph_set.all()[0].get_data()
    return GraphSimilarity(a_graph, b_graph).ratio()


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


def compare(func_set_1, func_set_2):
    res_matrix = []
    for func1 in func_set_1:
        res_row = []
        for func2 in func_set_2:
            res = generate_matching_grade(func1.id, func2.id)
            res_row.append(res)
        res_matrix.append(res_row)
    return res_matrix


def extract_results_to_excel(path, func_set_1, func_set_2):
    book = xlwt.Workbook(encoding="utf-8")
    sheet1 = book.add_sheet("Sheet1")
    xlwt.Alignment.HORZ_CENTER
    xlwt.Alignment.VERT_CENTER
    res_mat = compare(func_set_1, func_set_2)
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


def extract_results_to_heat_map(path, func_set_1, func_set_2):
    res_mat = compare(func_set_1, func_set_2)
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


def get_top_similars(num_of_tops, func, func_set):
    similarity_res = []
    for compared_func in func_set:
        print (compared_func.id, func.id)
        similarity_grade = generate_matching_grade(compared_func.id, func.id)
        similarity_res.append((similarity_grade, compared_func.func_name))

    return heapq.nlargest(num_of_tops, similarity_res)


def get_top_similars_for_all_funcs(func_set, num_of_tops, path):
    f = open(path, 'w')
    delimeter_line = \
         "\n###############################################################\n"
    for func in func_set:
        top_similars = get_top_similars(num_of_tops, func, func_set)
        f.write("%s: top similars\n" % str((func.func_name, func.exe_name)))
        for item in top_similars:
            f.write("%s, %.3f\n" % (item[1], item[0]))
        expected_similarities = \
            get_functions_with_similar_name(func.func_name, func_set)
        f.write("Expected:\n")
        for func in expected_similarities:
            f.write(str((func.func_name, func.exe_name)) + ', ')
        f.write(delimeter_line)
    f.close()


# TODO: separate comparison and extraction
def compare_exes_extract_to_excel(path, exe_name1, exe_name2):
    book = xlwt.Workbook(encoding="utf-8")
    sheet1 = book.add_sheet("Sheet1")

    exe1_funcs = Function.objects.filter(exe_name=exe_name1)
    exe2_funcs = Function.objects.filter(exe_name=exe_name2)
    exe1_func_names = [func.func_name for func in exe1_funcs]
    exe2_func_names = [func.func_name for func in exe2_funcs]
    exe1_compared_funcs = []
    exe2_compared_funcs = []
    res_arr = []
    arr_row = []
    compared_func_names = set(exe1_func_names) & set(exe2_func_names)
    for excluded in EXCLUDED_ON_EXE_COMPARISON:
        compared_func_names = filter(lambda n: excluded not in n,
                                     compared_func_names)

    for n in compared_func_names:
        exe1_compared_funcs.append(exe1_funcs.get(func_name=n))
        exe2_compared_funcs.append(exe2_funcs.get(func_name=n))

    exe1_compared_funcs = exe1_compared_funcs[0:100]
    exe2_compared_funcs = exe2_compared_funcs[0:100]
    i = 1

    for func1 in exe1_compared_funcs:
        j = 1
        sheet1.write(0, i, func1.func_name)
        sheet1.write(i, 0, func1.func_name)
        for func2 in exe2_compared_funcs:
            print (func1.id, func2.id)
            res = generate_matching_grade(func1.id, func2.id)
            arr_row.append(res)
            sheet1.write(i, j, res)
            j += 1
        i += 1
        res_arr.append(arr_row)
        arr_row = []

    data = np.array(res_arr)
    fig, ax = plt.subplots()
    heatmap = ax.pcolor(data, cmap=plt.cm.Blues)  # @UndefinedVariable
    ax.set_xticks(np.arange(data.shape[0]) + 0.5, minor=False)
    ax.set_yticks(np.arange(data.shape[1]) + 0.5, minor=False)
    ax.invert_yaxis()
    ax.xaxis.tick_top()
    ax.set_xticklabels(compared_func_names, minor=False)
    ax.set_yticklabels(compared_func_names, minor=False)

    plt.xticks(rotation=90)
    plt.rcParams.update({'font.size': 4})
    # fig.tight_layout()
    plt.savefig("C:\\Users\\user\\Desktop\\test.pdf", bbox_inches='tight', dpi=100)
    plt.show()
    book.save(path)

