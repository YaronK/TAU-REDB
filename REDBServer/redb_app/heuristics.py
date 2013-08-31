"""
Heuristics for comparing attribute instances.
"""

# standard library imports
from difflib import SequenceMatcher
import networkx as nx
import networkx.algorithms as graph_alg
from utils import CliquerGraph
import matplotlib.pyplot as plt
import copy


MIN_HEIGHT_RATIO = 0.2
MAX_GRAPH_COMP_SIZE = 20000
BLOCK_SIMILARITY_THRESHOLD = 0.85

ITYPES_WEIGHT = 0.7
STRINGS_WEIGHT = 0.075
CALLS_WEIGHT = 0.15
IMMS_WEIGHT = 0.075

MIN_BLOCK_WEIGHT_DELTA = 0.1
MIN_RATIO = 0.3
NEGLACTABLE_REMAINDER_RATIO = 0.1


class Heuristic:
    """ Represents a single attribute. """
    def __init__(self, instnace_1, instance_2):
        """
        Initializes Heuristic class with two attribute instances and computes
        similarity grade with regard to the heuristic and attribute.
        """
        pass

    def ratio(self):
        """ Retrieves Results """
        pass


class DictionarySimilarity(Heuristic):
    """
    Grades dictionaries similarity.
    """
    def __init__(self, dict1, dict2):
        self.a_dict = dict1
        self.b_dict = dict2
        self._ratio = None

    def ratio(self):
        if (self._ratio == None):
            a_keys = set(self.a_dict.keys())
            b_keys = set(self.b_dict.keys())
            c_s = a_keys.union(b_keys)

            f_sum = 0
            d_sum = 0
            for c in c_s:
                a_value = 0
                if (c in a_keys):
                    a_value = int(self.a_dict[c])
                b_value = 0
                if (c in b_keys):
                    b_value = int(self.b_dict[c])

                minimum = (float)(min(a_value, b_value))
                maximum = (float)(max(a_value, b_value))
                f_sum += a_value + b_value
                d_sum += (a_value + b_value) * (minimum / maximum)

            if (f_sum):
                self._ratio = d_sum / f_sum
            else:
                self._ratio = 1.0
        return self._ratio


class BlockSimilarity(Heuristic):
    def __init__(self, block_data_1, block_data_2,
                 graph_height_1, graph_height_2):
        self.block_data_1 = block_data_1
        self.block_data_2 = block_data_2
        self.graph_height_1 = graph_height_1
        self.graph_height_2 = graph_height_2
        self._ratio = None

    def ratio(self,):
        if self.block_data_1 == self.block_data_2:
            return 1.0

        distance = abs(self.block_data_1["dist_from_root"] -
                       self.block_data_2["dist_from_root"])
        max_height = max(self.graph_height_1, self.graph_height_2)
        try:
            height_ratio = distance / float(max_height)
        except Exception:
            height_ratio = 0
        if height_ratio > MIN_HEIGHT_RATIO:
            # nodes are too far apart
            return 0.0

        return (ITYPES_WEIGHT * self.itypes_similarity() + \
                STRINGS_WEIGHT * self.strings_similarity() + \
                CALLS_WEIGHT * self.call_similarity() + \
                IMMS_WEIGHT * self.immediates_similarity())

    def itypes_similarity(self):
        return SequenceMatcher(a=self.block_data_1["itypes"],
                               b=self.block_data_2["itypes"],
                               autojunk=False).ratio()

    def strings_similarity(self):
        return SequenceMatcher(a=self.block_data_1["strings"],
                               b=self.block_data_2["strings"]).ratio()

    def call_similarity(self):
        return SequenceMatcher(a=self.block_data_1["calls"],
                               b=self.block_data_2["calls"]).ratio()

    def immediates_similarity(self):
        return SequenceMatcher(a=self.block_data_1["imms"],
                               b=self.block_data_2["imms"]).ratio()


class GraphSimilarity(Heuristic):
    def __init__(self, graph_1, graph_2):
        self.graph_1 = graph_1
        self.graph_2 = graph_2
        """
        nx.draw(graph_1)
        plt.show()
        nx.draw(graph_2)
        plt.show()
        """
        self.graph_height_1 = \
            max(nx.single_source_dijkstra_path_length(self.graph_1,
                                                   0).values())
        self.graph_height_2 = \
            max(nx.single_source_dijkstra_path_length(self.graph_2,
                                                      0).values())
        if self.graph_1.number_of_nodes() * self.graph_2.number_of_nodes() > 2500:
            self.BLOCK_SIMILARITY_THRESHOLD = 0.9
        else:
            self.BLOCK_SIMILARITY_THRESHOLD = 0.7

    def ratio(self):
        """
        if self.graph_1.edges() == self.graph_2.edges():
            if self.graph_1.nodes(data='true') == self.graph_2.nodes(data='true'):
                return 1.0
            elif self.graph_1.number_of_nodes() == self.graph_2.number_of_nodes():
                return self.avg_block_sim_given_equal_edges()
        """
        return self.compare_graphs()

    def avg_block_sim_given_equal_edges(self):
        f_sum = 0
        d_sum = 0

        for block_num in range(self.graph_1.number_of_nodes()):
            block_data_1 = self.graph_1.node[block_num]['data']
            block_data_2 = self.graph_2.node[block_num]['data']
            ratio = \
             BlockSimilarity(block_data_1, block_data_2, self.graph_height_1,
                             self.graph_height_2).ratio()
            len_1 = float(len(block_data_1["itypes"]))
            len_2 = float(len(block_data_2["itypes"]))
            f_sum += (len_1 + len_2)
            d_sum += (len_1 + len_2) * ratio
        return d_sum / f_sum

    def calc_block_similarities(self):
        block_pairs = []
        for i in range(self.num_nodes_graph_1):
            block_data_1 = self.graph_1.node[i]['data']
            for j in range(self.num_nodes_graph_2):
                block_data_2 = self.graph_2.node[j]['data']
                sim = BlockSimilarity(block_data_1, block_data_2,
                                      self.graph_height_1,
                                      self.graph_height_2).ratio()
                block_pairs.append((i, j, sim))
        self.block_similarities = block_pairs

    def find_more_cliques(self):
        if self.first_iteration:
            self.first_iteration = False
            return True
        if (self.size_of_last_clique_found / float(self.size_of_min_graph) <
            MIN_RATIO):
            return False
        """
        if (self.association_graph.number_of_nodes() <
            len(self.compared_block_pairs) * NEGLACTABLE_REMAINDER_RATIO):
            return False
        """
        return True

    def merge_all_blocks(self, graph):
        merged_block = {}
        merged_block["itypes"] = []
        merged_block["calls"] = ""
        merged_block["strings"] = ""
        merged_block["imms"] = []
        for block_num in range(graph.number_of_nodes()):
            block_data = graph.node[block_num]['data']
            merged_block["itypes"].append(block_data["itypes"])
            merged_block["calls"] += block_data["calls"]
            merged_block["strings"] += block_data["strings"]
            merged_block["imms"].append(block_data["imms"])
        merged_block["dist_from_root"] = 0
        return merged_block

    def get_similar_block_pairs(self):
        pairs = []
        for (a, b, w) in self.block_similarities:
            if w >= self.BLOCK_SIMILARITY_THRESHOLD:
                pairs.append((a, b, w))
        return pairs

    def calc_association_graph(self, nodes):
        num_of_nodes = len(nodes)
        graph = CliquerGraph(num_of_nodes)
        for node_index in range(num_of_nodes):
            w = nodes[node_index][2]
            graph.set_vertex_weight(node_index, int(w * 1000))
        graph_1_edges = self.graph_1.edges()
        graph_2_edges = self.graph_2.edges()
        for x in range(num_of_nodes):
            (i, s, _) = nodes[x]
            for y in range(num_of_nodes):
                (j, t, _) = nodes[y]
                if s != t and i != j:
                    if ((((i, j) in graph_1_edges) and
                         ((s, t) in graph_2_edges)) or
                        (((i, j) not in graph_1_edges) and
                         ((s, t) not in graph_2_edges))):
                        graph.add_edge(x, y)
        self.association_graph = graph

    def get_max_clique_wrt_weight(self):
        def clique_weight(c):
            node_weights = [self.association_graph.node[n]['weight']
                            for n in c]
            return sum(node_weights)

        cliques = list(graph_alg.find_cliques(self.association_graph))
        clique_weights = [clique_weight(c) for c in cliques]
        max_weight = max(clique_weights)
        max_clique = cliques[clique_weights.index(max_weight)]

        return max_clique, max_weight

    def filter_out_clique(self, clique):
        temp_pairs = copy.deepcopy(self.compared_block_pairs)
        filtered_pairs = copy.deepcopy(self.compared_block_pairs)
        for node_index in clique:
            b1, b2, _ = self.compared_block_pairs[node_index]
            # print str(node_index) + ": " + str((b1, b2))
            for x, y, w in temp_pairs:
                if x == b1 or y == b2:
                    if (x, y, w) in filtered_pairs:
                        filtered_pairs.remove((x, y, w))
        return filtered_pairs
        """
        for node_index in nodes_to_be_removed:
            for other_node_index in range(len(self.compared_block_pairs)):
                self.association_graph.remove_edge(node_index,
                                                   other_node_index)
                self.association_graph.remove_edge(other_node_index,
                                                   node_index)
        """
    def get_clique_weight(self, clique):
        weight = 0.0
        for i in clique:
            weight += self.compared_block_pairs[i][2]
        return weight

    def compare_graphs(self):
        self.num_nodes_graph_1 = self.graph_1.number_of_nodes()
        self.num_nodes_graph_2 = self.graph_2.number_of_nodes()
        self.size_of_min_graph = min(self.num_nodes_graph_1,
                                     self.num_nodes_graph_2)
        self.first_iteration = True
        self.num_of_cliques_found = 0
        self.total_weight = 0.0
        self.total_size = 0
        self.calc_block_similarities()

        self.compared_block_pairs = self.get_similar_block_pairs()
        if len(self.compared_block_pairs) == 0:
            return 0.0


        """
        if self.association_graph.number_of_edges() == 0:
            return 0.0
        """
        filtered_pairs = self.compared_block_pairs
        continue_to_next_iteration = 1
        while self.find_more_cliques() and continue_to_next_iteration:
            if len(filtered_pairs) == 0:
                # print "bye"
                break
            self.calc_association_graph(filtered_pairs)

            if self.association_graph.edge_count() >= MAX_GRAPH_COMP_SIZE:
                merged_block_graph1 = self.merge_all_blocks(self.graph_1)
                merged_block_graph2 = self.merge_all_blocks(self.graph_2)
                self.association_graph.free()
                return BlockSimilarity(merged_block_graph1,
                                       merged_block_graph2,
                                       self.graph_height_1,
                                       self.graph_height_2).ratio()
            print "in cliquer"
            clique = self.association_graph.get_maximum_clique()
            print "out cliquer"
            weight = self.get_clique_weight(clique)
            self.size_of_last_clique_found = len(clique)
            self.total_weight += weight
            self.total_size += self.size_of_last_clique_found
            self.num_of_cliques_found += 1
            filtered_pairs = self.filter_out_clique(clique)
            self.association_graph.free()
            continue_to_next_iteration = 0

        res = self.total_weight / float(self.num_nodes_graph_1 +
                                   self.num_nodes_graph_2 - self.total_weight)
        print res
        return res
