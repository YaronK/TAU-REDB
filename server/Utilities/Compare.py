from redb_app import graph, actions, utils
from redb_app.models import Function
import json
import xlwt
from redb_app.heuristics import GraphSimilarity


def generate_matching_grade(a_id, b_id):
    a_graph = create_graph(a_id)
    b_graph = create_graph(b_id)
    return GraphSimilarity(a_graph, b_graph).ratio()


def create_graph(g_id):
    g_func = Function.objects.get(id=g_id)
    g_edges = json.loads(g_func.graph.edges)
    g_dist_from_root = json.loads(g_func.graph.dist_from_root.replace("'",
                                                                      '"'),
                                  object_hook=utils._decode_dict)
    g_blocks = actions.generate_db_func_blocks(g_func, g_dist_from_root)
    return graph.Graph(g_blocks, g_edges)


EXCLUDED_ON_EXE_COMPARISON = ["unknown", "sub_"]


# TODO: separate comparison and extraction
def compare_exes_extract_to_excel(path, exe_name1, exe_name2):
    book = xlwt.Workbook(encoding="utf-8")
    sheet1 = book.add_sheet("Sheet1")

    exe1_funcs = Function.objects.filter(exe_name=exe_name1)
    exe2_funcs = Function.objects.filter(exe_name=exe_name2)
    exe1_func_names = [func.name for func in exe1_funcs]
    exe2_func_names = [func.name for func in exe2_funcs]
    exe1_compared_funcs = []
    exe2_compared_funcs = []

    compared_func_names = set(exe1_func_names) & set(exe2_func_names)
    for excluded in EXCLUDED_ON_EXE_COMPARISON:
        compared_func_names = filter(lambda n: excluded not in n,
                                     compared_func_names)

    for n in compared_func_names:
        exe1_compared_funcs.append(exe1_funcs.get(name=n))
        exe2_compared_funcs.append(exe2_funcs.get(name=n))

    i = 1
    for func1 in exe1_compared_funcs:
        j = 1
        sheet1.write(0, i, func1.name)
        sheet1.write(i, 0, func1.name)
        for func2 in exe2_compared_funcs:
            res = generate_matching_grade(func1.id, func2.id)
            print (i, j, res)
            sheet1.write(i, j, res)
            j += 1
        i += 1

    book.save(path)
