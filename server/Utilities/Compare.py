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
    g_dist_from_root = json.loads(g_func.graph.dist_from_root.replace("'", '"'), 
                                                         object_hook=utils._decode_dict)
    g_blocks = actions.generate_db_func_blocks(g_func, g_dist_from_root)
    return graph.Graph(g_blocks, g_edges)

def compare_and_extract_to_excel(path, exe_name1, exe_name2):
    book = xlwt.Workbook(encoding="utf-8")
    sheet1 = book.add_sheet("Sheet1")
    funcs_exe1 = Function.objects.filter(exe_name=exe_name1)
    funcs_exe2 = Function.objects.filter(exe_name=exe_name2)
    funcs_exe1_names = [func.name for func in funcs_exe1]
    funcs_exe2_names = [func.name for func in funcs_exe2]
    intersect_exe1 =[]
    intersect_exe2 =[]
    intersect_names = set(funcs_exe1_names) & set(funcs_exe2_names) 
    for n in intersect_names:
        if "unknown" not in n and "sub_" not in n:
            intersect_exe1.append(funcs_exe1.get(name=n))
            intersect_exe2.append(funcs_exe2.get(name=n))
    i = 1
    for func1 in intersect_exe1:
        j = 1
        sheet1.write(0, i, func1.name)
        sheet1.write(i, 0, func1.name)
        for func2 in intersect_exe2:
            res = generate_matching_grade(func1.id, func2.id)
            print (i, j, res)
            sheet1.write(i, j, res)
            j += 1
        i +=1
    book.save(path) 
            