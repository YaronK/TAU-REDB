"""
Heuristics for comparing attribute instances.
"""

# standard library imports
from difflib import SequenceMatcher
import networkx as nx
from utils import CliquerGraph, FlexibleSequenceMatcher, test_log

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

    def ratio(self):
        if self._ratio == None:
            if self.block_data_1 == self.block_data_2:
                return 1.0
            self._ratio = FlexibleSequenceMatcher(
                flexibility=constants.block_similarity.STR_UNICODE_FLEXIBILITY,
                a=self.block_data_1["block_data"],
                b=self.block_data_2["block_data"]).ratio()
        return self._ratio

    def get_similarities(self):
        return [self.itypes_similarity(),
                self.strings_similarity(),
                self.calls_similarity(),
                self.immediates_similarity()]

    def itypes_similarity(self):
        if ((len(self.block_data_1["itypes"]) == 0) and
            (len(self.block_data_2["itypes"]) == 0)):
            return None
        else:
            return SequenceMatcher(a=self.block_data_1["itypes"],
                                   b=self.block_data_2["itypes"]).ratio()

    def strings_similarity(self):
        if ((len(self.block_data_1["strings"]) == 0) and
            (len(self.block_data_2["strings"]) == 0)):
            return None
        else:
            return SequenceMatcher(a=self.block_data_1["strings"],
                                   b=self.block_data_2["strings"]).ratio()

    def calls_similarity(self):
        if ((len(self.block_data_1["calls"]) == 0) and
            (len(self.block_data_2["calls"]) == 0)):
            return None
        else:
            return SequenceMatcher(a=self.block_data_1["calls"],
                                   b=self.block_data_2["calls"]).ratio()

    def immediates_similarity(self):
        if ((len(self.block_data_1["imms"]) == 0) and
            (len(self.block_data_2["imms"]) == 0)):
            return None
        else:
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

    def ratio(self, test_dict=None):
        """
        if the block_pairs_similarities arg is not supplied, the block
        similarities are computed.
        """

        self.set_constants(test_dict=test_dict)

        if self.structure_and_attribues_are_equal():
            self.log_decision("structure_and_attribues_are_equal")
            return 1.0

        if self.structure_is_equal():
            self.log_decision("structure_is_equal, ratio_given_similar_structures")
            ratio = self.ratio_given_similar_structures()
            self.log_decision("ratio: " + str(ratio))
            return ratio

        self.block_pairs_similarities = self.calc_block_similarities()
        self.filter_non_similar_block_pairs()
        self.filter_distant_block_pairs()

        self.log_decision("remaining block pairs = " +
                          str(len(self.block_pairs_similarities)))
        if len(self.block_pairs_similarities) == 0:
            self.log_decision("ratio_treat_as_one_block")
            ratio = self.ratio_treat_as_one_block()
            self.log_decision("ratio: " + str(ratio))
            return ratio

        self.calc_association_graph(self.block_pairs_similarities)
        self.log_decision("association_graph.edge_count(): " +
                          str(self.association_graph.edge_count()))

        if self.association_graph_too_few_edges():
            self.log_decision("association_graph_too_few_edges, " +
                              "ratio_treat_as_one_block")
            self.association_graph.free()
            ratio = self.ratio_treat_as_one_block()
            self.log_decision("ratio: " + str(ratio))
            return ratio
        elif self.association_graph_too_many_edges():
            self.log_decision("association_graph_too_many_edges, " +
                              "ratio_treat_as_one_block")
            self.association_graph.free()
            ratio = self.ratio_treat_as_one_block()
            self.log_decision("ratio: " + str(ratio))
            return ratio
        else:
            self.log_decision("ratio_using_association_graph")
            ratio = self.ratio_using_association_graph()
            self.log_decision("ratio: " + str(ratio))
            return ratio

    def set_constants(self, test_dict=None):
        self.log_decisions = test_dict and "log_decisions" in test_dict

        if test_dict and "block_similarity_threshold" in test_dict:
            self.block_similarity_threshold = \
                test_dict["block_similarity_threshold"]
        else:
            self.block_similarity_threshold = \
                constants.block_similarity.BLOCK_SIMILARITY_THRESHOLD

        if test_dict and "association_graph_max_size" in test_dict:
            self.association_graph_max_size = \
                test_dict["association_graph_max_size"]
        else:
            self.association_graph_max_size = \
                constants.graph_similarity.ASSOCIATION_GRAPH_MAX_SIZE

        if test_dict and "min_block_dist_similarity" in test_dict:
            self.min_block_dist_similarity = \
                test_dict["min_block_dist_similarity"]
        else:
            self.min_block_dist_similarity = \
                constants.block_similarity.MIN_BLOCK_DIST_SIMILARITY

        self.log_decision("block_similarity_threshold: " +
                          str(self.block_similarity_threshold) +
                          ", association_graph_max_size: " +
                          str(self.association_graph_max_size) +
                          ", min_block_dist_similarity: " +
                          str(self.min_block_dist_similarity))

    def ratio_given_similar_structures(self):
        f_sum = 0
        d_sum = 0

        for block_num in range(self.graph_1.number_of_nodes()):

            block_data_1 = self.graph_1.node[block_num]['data']
            block_data_2 = self.graph_2.node[block_num]['data']

            ratio = BlockSimilarity(block_data_1, block_data_2,
                                    self.graph_height_1,
                                    self.graph_height_2).ratio()

            len_1 = float(len(block_data_1["block_data"]))
            len_2 = float(len(block_data_2["block_data"]))
            f_sum += (len_1 + len_2)
            d_sum += (len_1 + len_2) * ratio
        return d_sum / f_sum

    def ratio_treat_as_one_block(self):
        merged_block_graph1 = self.merge_all_blocks(self.graph_1)
        merged_block_graph2 = self.merge_all_blocks(self.graph_2)

        return BlockSimilarity(merged_block_graph1,
                               merged_block_graph2,
                               self.graph_height_1,
                               self.graph_height_2).ratio()

    def calc_block_similarities(self):
        block_pairs = []
        for i in range(self.num_nodes_graph_1):
            block_data_1 = self.graph_1.node[i]['data']
            for j in range(self.num_nodes_graph_2):
                block_data_2 = self.graph_2.node[j]['data']
                block_sim = BlockSimilarity(block_data_1, block_data_2,
                                      self.graph_height_1,
                                      self.graph_height_2)
                data_similarity = block_sim.ratio()
                distance_similarity = block_sim.distance_from_root_similarity()
                block_pairs.append((i, j, data_similarity,
                                    distance_similarity))
        return block_pairs

    def merge_all_blocks(self, graph):
        merged_block = {}
        merged_block["block_data"] = []

        for block_num in range(graph.number_of_nodes()):
            block_data = graph.node[block_num]['data']
            merged_block["block_data"] += block_data["block_data"]
        merged_block["dist_from_root"] = 0
        return merged_block

    def filter_non_similar_block_pairs(self):
        pairs = []
        for (a, b, data_sim, distance_sim) in self.block_pairs_similarities:
            if data_sim >= self.block_similarity_threshold:
                pairs.append((a, b, data_sim, distance_sim))
        self.block_pairs_similarities = pairs

    def filter_distant_block_pairs(self):
        pairs = []
        for (a, b, data_sim, distance_sim) in self.block_pairs_similarities:
            if distance_sim >= self.min_block_dist_similarity:
                pairs.append((a, b, data_sim, distance_sim))
        self.block_pairs_similarities = pairs

    def calc_association_graph(self, nodes):
        num_of_nodes = len(nodes)
        graph = CliquerGraph(num_of_nodes)
        for node_index in range(num_of_nodes):
            data_similarity = nodes[node_index][2]
            graph.set_vertex_weight(node_index, int(data_similarity * 1000))

        for x in range(num_of_nodes):
            (i, s, data_sim, _) = nodes[x]
            for y in range(num_of_nodes):
                (j, t, data_sim, _) = nodes[y]
                if s != t and i != j:
                    if ((self.graph_1.has_edge(i, j) and
                         self.graph_2.has_edge(s, t)) or
                        (not self.graph_1.has_edge(i, j) and
                         not self.graph_2.has_edge(s, t))):
                        graph.add_edge(x, y)
        self.association_graph = graph

    def get_clique_weight(self, clique):
        weight = 0.0
        for i in clique:
            weight += self.block_pairs_similarities[i][2]
        return weight

    def ratio_using_association_graph(self):
        #print "in cliquer"
        clique = self.association_graph.get_maximum_clique()
        #print "out cliquer"

        weight = self.get_clique_weight(clique)

        self.association_graph.free()

        res = weight / (float(self.num_nodes_graph_1 +
                              self.num_nodes_graph_2 - weight))
        # print res
        return res

    def structure_and_attribues_are_equal(self):
        return self.structure_is_equal and self.attributes_are_equal()

    def structure_is_equal(self):
        return self.graph_1_edges == self.graph_2_edges

    def attributes_are_equal(self):
        return self.graph_1.nodes(data=True) == self.graph_2.nodes(data=True)

    def association_graph_too_many_edges(self):
        return (self.association_graph.edge_count() >=
                self.association_graph_max_size)

    def association_graph_too_few_edges(self):
        return (self.association_graph.edge_count() == 0)

    def log_decision(self, string):
        if self.log_decisions:
            test_log(string)
