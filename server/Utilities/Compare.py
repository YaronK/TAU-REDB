from redb_app import graph, actions
from redb_app.models import Function
import json
from redb_app.heuristics import GraphSimilarity


def generate_matching_grade(a_id, b_id):
    a_graph = create_graph(a_id)
    b_graph = create_graph(b_id)

    print (a_id, b_id, GraphSimilarity(a_graph, b_graph).ratio())


def create_graph(g_id):
    g_func = Function.objects.get(id=g_id)
    g_edges = json.loads(g_func.graph.edges)
    g_blocks = actions.generate_db_func_blocks(g_func)
    return graph.Graph(g_blocks, g_edges)
