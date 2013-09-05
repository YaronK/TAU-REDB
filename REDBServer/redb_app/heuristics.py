"""
Heuristics for comparing attribute instances.
"""

# standard library imports
from difflib import SequenceMatcher
import networkx as nx
import networkx.algorithms as graph_alg
from utils import CliquerGraph
import copy

import constants


class Heuristic:
    """ Represents a single attribute. """
    def __init__(self, instnace_1, instance_2):
        """
        Initializes Heuristic class with two attribute instances and computes
        similarity grade with regard to the heuristic and attribute.
        """
        pass

    def ratio(self, weights=None):
        """
        weights is a dictionary containing attr-weight pairs,
        where attr is a string, and weight is a float. i.e. {'itypes': 0.4}.
        if the weights arg is not supplied, default weights are taken.
        """
        pass


class DictionarySimilarity(Heuristic):
    """
    Grades dictionaries similarity.
    """
    def __init__(self, dict1, dict2):
        self.a_dict = dict1
        self.b_dict = dict2
        self._ratio = None

    def ratio(self, weights=None):  # @UnusedVariable
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


class FrameSimilarity(Heuristic):
    def __init__(self, args_size_func_1, vars_size_func_1, regs_size_func_1,
                 args_size_func_2, vars_size_func_2, regs_size_func_2):
        self.args_size_func_1 = args_size_func_1
        self.vars_size_func_1 = vars_size_func_1
        self.regs_size_func_1 = regs_size_func_1
        self.args_size_func_2 = args_size_func_2
        self.vars_size_func_2 = vars_size_func_2
        self.regs_size_func_2 = regs_size_func_2
        self._ratio = None

    def ratio(self, weights=None):
        if (self._ratio == None):
            if weights == None:
                const = constants.frame_similarity
                args_size_weight = const.ARGS_SIZE_WEIGHT
                vars_size_weight = const.VARS_SIZE_WEIGHT
                regs_size_weight = const.REGS_SIZE_WEIGHT
            else:
                args_size_weight = weights['args_size']
                vars_size_weight = weights['vars_size']
                regs_size_weight = weights['regs_size']

            self._ratio = (args_size_weight * self.args_size_similarity() +
                    vars_size_weight * self.vars_size_similarity() +
                    regs_size_weight * self.regs_size_similarity())
        return self._ratio

    def get_similarities(self):
        return [self.args_size_similarity(),
                self.vars_size_similarity(),
                self.regs_size_similarity()]

    def regs_size_similarity(self):
        max_regs_size = max(self.regs_size_func_1, self.regs_size_func_2)
        if  max_regs_size == 0:
            return 1.0
        else:
            return (1 - abs(self.regs_size_func_1 -
                            self.regs_size_func_2) / float(max_regs_size))

    def args_size_similarity(self):
        max_args_size = max(self.args_size_func_1, self.args_size_func_2)
        if  max_args_size == 0:
            return 1.0
        else:
            return (1 - abs(self.args_size_func_1 -
                            self.args_size_func_2) / float(max_args_size))

    def vars_size_similarity(self):
        max_vars_size = max(self.vars_size_func_1, self.vars_size_func_2)
        if  max_vars_size == 0:
            return 1.0
        else:
            return (1 - abs(self.vars_size_func_1 -
                            self.vars_size_func_2) / float(max_vars_size))


class BlockSimilarity(Heuristic):
    def __init__(self, block_data_1, block_data_2,
                 graph_height_1, graph_height_2):
        self.block_data_1 = block_data_1
        self.block_data_2 = block_data_2
        self.graph_height_1 = graph_height_1
        self.graph_height_2 = graph_height_2
        self._ratio = None

    def ratio(self, weights=None):
        if self._ratio == None:
            if self.block_data_1 == self.block_data_2:
                return 1.0

            if weights is None:
                const = constants.block_similarity
                itypes_weight = const.ITYPES_WEIGHT
                strings_weight = const.STRINGS_WEIGHT
                calls_weight = const.CALLS_WEIGHT
                imms_weight = const.IMMS_WEIGHT
                dist_from_root_weight = const.DIST_FROM_ROOT_WEIGHT
            else:
                itypes_weight = weights['itypes']
                strings_weight = weights['strings']
                calls_weight = weights['calls']
                imms_weight = weights['imms']
                dist_from_root_weight = weights['dist_from_root']

            self._ratio = (itypes_weight * self.itypes_similarity() +
                           strings_weight * self.strings_similarity() +
                           calls_weight * self.call_similarity() +
                           imms_weight * self.immediates_similarity() +
                           dist_from_root_weight *
                           self.distance_from_root_similarity())
        return self._ratio

    def get_similarities(self):
        distance_from_root_similarity = self.distance_from_root_similarity()
        if (distance_from_root_similarity <
            constants.block_similarity.MIN_BLOCK_DIST_SIMILARITY):
            return [0, 0, 0, 0, 0]
        return [self.itypes_similarity(),
                self.strings_similarity(),
                self.call_similarity(),
                self.immediates_similarity(),
                self.distance_from_root_similarity()]

    def itypes_similarity(self):
        return SequenceMatcher(a=self.block_data_1["itypes"],
                               b=self.block_data_2["itypes"]).ratio()

    def strings_similarity(self):
        return SequenceMatcher(a=self.block_data_1["strings"],
                               b=self.block_data_2["strings"]).ratio()

    def call_similarity(self):
        return SequenceMatcher(a=self.block_data_1["calls"],
                               b=self.block_data_2["calls"]).ratio()

    def immediates_similarity(self):
        return SequenceMatcher(a=self.block_data_1["imms"],
                               b=self.block_data_2["imms"]).ratio()

    def distance_from_root_similarity(self):
        block_dist_delta = abs(self.block_data_1["dist_from_root"] -
                               self.block_data_2["dist_from_root"])
        graph_max_height = max(self.graph_height_1, self.graph_height_2)

        if (graph_max_height == 0):  # both graphs contain only a single node
            return 1.0
        else:
            return (1.0 - block_dist_delta / float(graph_max_height))


class GraphSimilarity(Heuristic):
    def __init__(self, graph_1, graph_2):
        self.graph_1 = graph_1
        self.graph_2 = graph_2

        self.num_nodes_graph_1 = self.graph_1.number_of_nodes()
        self.num_nodes_graph_2 = self.graph_2.number_of_nodes()

        self.graph_1_edges = self.graph_1.edges()
        self.graph_2_edges = self.graph_2.edges()

        self.size_of_min_graph = min(self.num_nodes_graph_1,
                                     self.num_nodes_graph_2)

        self.graph_height_1 = \
            max(nx.single_source_dijkstra_path_length(self.graph_1,
                                                   0).values())
        self.graph_height_2 = \
            max(nx.single_source_dijkstra_path_length(self.graph_2,
                                                      0).values())

    def ratio(self, block_similarity_tuples=None, weights=None):
        """
        if the block_similarities arg is not supplied, the block similarities
        are computed.
        """
        if self.structure_and_attribues_are_equal():
            return 1.0

        if self.structure_is_equal():
            return self.ratio_given_similar_structures(block_similarity_tuples)

        if block_similarity_tuples:
            self.block_similarities = block_similarity_tuples
        else:
            self.block_similarities = self.calc_block_similarities()

        self.compared_block_pairs = \
            self.get_similar_block_pairs()
        if len(self.compared_block_pairs) == 0:
            return 0.0

        self.calc_association_graph(self.compared_block_pairs)
        if self.association_graph_too_big():
            return self.ratio_treat_as_one_block(weights)
        else:
            return self.ratio_using_association_graph()

    def ratio_given_similar_structures(self, block_similarity_tuples):
        f_sum = 0
        d_sum = 0
        if block_similarity_tuples is not None:
            similarity_tuples = filter(lambda (x, y, _): (x == y),
                                       block_similarity_tuples)
        for block_num in range(self.graph_1.number_of_nodes()):
            if block_similarity_tuples is not None:
                single_tuple = filter(lambda (x, y, _): x == block_num,
                                      similarity_tuples)[0]
                ratio = single_tuple[2]
            block_data_1 = self.graph_1.node[block_num]['data']
            block_data_2 = self.graph_2.node[block_num]['data']
            if block_similarity_tuples is None:
                ratio = BlockSimilarity(block_data_1, block_data_2,
                                        self.graph_height_1,
                                        self.graph_height_2).ratio()
            len_1 = float(len(block_data_1["itypes"]))
            len_2 = float(len(block_data_2["itypes"]))
            f_sum += (len_1 + len_2)
            d_sum += (len_1 + len_2) * ratio
        return d_sum / f_sum

    def ratio_treat_as_one_block(self, weights):
        merged_block_graph1 = self.merge_all_blocks(self.graph_1)
        merged_block_graph2 = self.merge_all_blocks(self.graph_2)
        self.association_graph.free()
        return BlockSimilarity(merged_block_graph1,
                               merged_block_graph2,
                               self.graph_height_1,
                               self.graph_height_2).ratio(weights)

    def calc_block_similarities(self, test=False):
        block_pairs = []
        for i in range(self.num_nodes_graph_1):
            block_data_1 = self.graph_1.node[i]['data']
            for j in range(self.num_nodes_graph_2):
                block_data_2 = self.graph_2.node[j]['data']
                if test:
                    sim = BlockSimilarity(block_data_1, block_data_2,
                                      self.graph_height_1,
                                      self.graph_height_2).get_similarities()
                else:
                    sim = BlockSimilarity(block_data_1, block_data_2,
                                          self.graph_height_1,
                                          self.graph_height_2).ratio()
                block_pairs.append((i, j, sim))
        return block_pairs

    def find_more_cliques(self):
        if self.first_iteration:
            self.first_iteration = False
            return True

        # not first iteration
        clique_graph_ratio = (self.size_of_last_clique_found /
                              float(self.size_of_min_graph))
        if (clique_graph_ratio <
            constants.graph_similarity.MIN_CLIQUE_GRAPH_RATIO):
            return False
        return True

    def merge_all_blocks(self, graph):
        merged_block = {}
        merged_block["itypes"] = []
        merged_block["calls"] = ""
        merged_block["strings"] = ""
        merged_block["imms"] = []
        for block_num in range(graph.number_of_nodes()):
            block_data = graph.node[block_num]['data']
            merged_block["itypes"] += block_data["itypes"]
            merged_block["calls"] += block_data["calls"]
            merged_block["strings"] += block_data["strings"]
            merged_block["imms"] += block_data["imms"]
        merged_block["dist_from_root"] = 0
        return merged_block

    def get_similar_block_pairs(self):
        pairs = []
        for (a, b, w) in self.block_similarities:
            if w >= constants.block_similarity.BLOCK_SIMILARITY_THRESHOLD:
                pairs.append((a, b, w))
        return pairs

    def calc_association_graph(self, nodes):
        num_of_nodes = len(nodes)
        graph = CliquerGraph(num_of_nodes)
        for node_index in range(num_of_nodes):
            w = nodes[node_index][2]
            graph.set_vertex_weight(node_index, int(w * 1000))

        for x in range(num_of_nodes):
            (i, s, _) = nodes[x]
            for y in range(num_of_nodes):
                (j, t, _) = nodes[y]
                if s != t and i != j:
                    if ((((i, j) in self.graph_1_edges) and
                         ((s, t) in self.graph_2_edges)) or
                        (((i, j) not in self.graph_1_edges) and
                         ((s, t) not in self.graph_2_edges))):
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
            for x, y, w in temp_pairs:
                if x == b1 or y == b2:
                    if (x, y, w) in filtered_pairs:
                        filtered_pairs.remove((x, y, w))
        return filtered_pairs

    def get_clique_weight(self, clique):
        weight = 0.0
        for i in clique:
            weight += self.compared_block_pairs[i][2]
        return weight

    def ratio_using_association_graph(self):
        self.first_iteration = True
        self.num_of_cliques_found = 0
        self.total_weight = 0.0
        self.total_size = 0

        while self.find_more_cliques() and (self.num_of_cliques_found == 0):
            # print "in cliquer"
            clique = self.association_graph.get_maximum_clique()
            # print "out cliquer"

            weight = self.get_clique_weight(clique)
            self.size_of_last_clique_found = len(clique)
            self.total_weight += weight
            self.total_size += self.size_of_last_clique_found
            self.num_of_cliques_found += 1
            filtered_pairs = self.filter_out_clique(clique)
            if len(filtered_pairs) == 0:
                break

            self.association_graph.free()
            self.calc_association_graph(filtered_pairs)

        res = self.total_weight / (float(self.num_nodes_graph_1 +
                                   self.num_nodes_graph_2 -
                                   self.total_weight))
        # print res
        return res

    def structure_and_attribues_are_equal(self):
        return self.structure_is_equal and self.attributes_are_equal()

    def structure_is_equal(self):
        return self.graph_1_edges == self.graph_2_edges

    def attributes_are_equal(self):
        return self.graph_1.nodes(data=True) == self.graph_2.nodes(data=True)

    def equal_number_of_nodes(self):
        return self.num_nodes_graph_1 == self.num_nodes_graph_2

    def association_graph_too_big(self):
        return (self.association_graph.edge_count() >=
                constants.graph_similarity.MAX_GRAPH_COMP_SIZE)
