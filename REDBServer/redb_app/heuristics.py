"""
Heuristics for comparing attribute instances.
"""

# standard library imports
from difflib import SequenceMatcher
from utils import CliquerGraph
from redb_app.utils import log_timing
import copy

MIN_HEIGHT_RATIO = 0.2
MAX_GRAPH_COMP_SIZE = 120
MINIMUM_NODE_WEIGHT = 0.8

ITYPES_WEIGHT = 0.6
STRINGS_WEIGHT = 0.1
CALLS_WEIGHT = 0.2
IMMS_WEIGHT = 0.1

MIN_BLOCK_WEIGHT_DELTA = 0.1
INITIAL_MIN_BLOCK_WEIGHT = 0.9
MIN_RATIO = 0.3


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
        height_ratio = distance / float(max_height)

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
        self.db_graph_1 = graph_1
        self.db_graph_2 = graph_2

        self.blocks_data_1 = [block.data() for block in
                              self.db_graph_1.block_set.all()]
        self.blocks_data_2 = [block.data() for block in
                              self.db_graph_2.block_set.all()]
        self.nx_graph_1 = graph_1.get_nx_graph()
        self.nx_graph_2 = graph_2.get_nx_graph()

    def ratio(self):
        if self.db_graph_1.edges == self.db_graph_2.edges:
            if self.blocks_data_1 == self.blocks_data_2:
                return 1.0
            elif len(self.blocks_data_1) == len(self.blocks_data_2):
                return self.avg_block_sim_given_equal_edges()
        return self.graph_similarity()

    def avg_block_sim_given_equal_edges(self):
        f_sum = 0
        d_sum = 0
        for block_num in range(len(self.blocks_data_1)):
            block_1 = self.blocks_data_1[block_num].data()
            block_2 = self.blocks_data_2[block_num].data()
            ratio = BlockSimilarity(block_1, block_2).ratio()
            len_1 = float(len(block_1["itypes"]))
            len_2 = float(len(block_2["itypes"]))

            f_sum += (len_1 + len_2)
            d_sum += (len_1 + len_2) * ratio
        return d_sum / f_sum

    @log_timing()
    def graph_similarity(self):
        def decrement_min_block_weight(weight):
            return weight - MIN_BLOCK_WEIGHT_DELTA

        def heavy_enough_pairs():
            heavy_enough_pairs = []
            for (a, b, w) in block_pairs:
                if w >= min_block_weight:
                    heavy_enough_pairs.append((a, b, w))
            return heavy_enough_pairs

        def get_association_graph(heavy_block_pairs):
            num_of_block_pairs = len(heavy_block_pairs)
            graph = CliquerGraph(num_of_block_pairs)
            for block_num in range(num_of_block_pairs):
                w = heavy_block_pairs[block_num][2]
                graph.set_vertex_weight(block_num, int(w * 1000))

            for x in range(num_of_block_pairs):
                for y in range(num_of_block_pairs):
                    (i, s, _) = heavy_block_pairs[x]
                    (j, t, _) = heavy_block_pairs[y]
                    if s != t and i != j:
                        if ((((i, j) in self.db_graph_1.edges) and
                             ((s, t) in self.db_graph_2.edges)) or
                            (((i, j) not in self.db_graph_1.edges) and
                             ((s, t) not in self.db_graph_2.edges))):
                            graph.add_edge(x, y)
            return graph

        def get_clique_weight(clique, heavy_block_pairs):
            weight = 0.0
            for i in clique:
                weight += heavy_block_pairs[i][2]
            return weight

        def filter_out_clique(heavy_block_pairs, clique):
            temp_pairs = copy.deepcopy(block_pairs)
            for i in clique:
                a, b, _ = heavy_block_pairs[i]
                for x, y, w in block_pairs:
                    if a == x or b == y:
                        if (x, y, w) in temp_pairs:
                            temp_pairs.remove(tuple((x, y, w)))

            return temp_pairs

        min_block_weight = INITIAL_MIN_BLOCK_WEIGHT

        block_pairs = []
        for i in range(len(self.db_graph_1.blocks)):
            block_1 = self.db_graph_1.blocks[i]
            for j in range(len(self.db_graph_2.blocks)):
                block_2 = self.db_graph_2.blocks[j]
                block_pairs.append((i, j,
                                    BlockSimilarity(block_1, block_2).ratio()))

        size_of_min_graph = min(len(self.db_graph_1.blocks),
                                len(self.db_graph_2.blocks))
        clique_size = size_of_min_graph
        total_weight = 0.0

        while (clique_size / float(size_of_min_graph) > MIN_RATIO):

            print "block_pairs: %d" % len(block_pairs)
            heavy_block_pairs = heavy_enough_pairs()
            print "heavy_block_pairs %d" % len(heavy_block_pairs)

            if len(heavy_block_pairs) == 0:
                print "bye"
                break

            association_graph = get_association_graph(heavy_block_pairs)
            print "in cliquer"
            clique = association_graph.get_max_clique()
            print "out cliquer"
            association_graph.free()

            clique_weight = get_clique_weight(clique, heavy_block_pairs)
            clique_size = len(clique)
            total_weight += clique_weight
            print ("clique! size: %d, weight: %f. min_block_weight: %f" %
                   (clique_size, clique_weight, min_block_weight))

            block_pairs = filter_out_clique(heavy_block_pairs, clique)

            #print len(block_pairs)
            # TODO: free clique!

            min_block_weight = decrement_min_block_weight(min_block_weight)
#             print "clique_size:"  + str(clique_size)
#             print "size_of_min_graph: " + str(size_of_min_graph)
#             print "ratio: " + str(clique_size / float(size_of_min_graph))
        res = total_weight / float(len(self.db_graph_1.blocks) +
                                   len(self.db_graph_2.blocks) -
                                   total_weight)
        return res
