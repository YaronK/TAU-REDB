from redb_app import actions, utils
from redb_app.models import Function
import json
import xlwt
from redb_app.heuristics import GraphSimilarity
import numpy as np
import matplotlib.pyplot as plt


def generate_matching_grade(a_id, b_id):
    a_graph = Function.objects.get(id=a_id).graph_set.all()[0].get_data()
    b_graph = Function.objects.get(id=b_id).graph_set.all()[0].get_data()
    return GraphSimilarity(a_graph, b_graph).ratio()


EXCLUDED_ON_EXE_COMPARISON = ["unknown", "sub_"]


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
