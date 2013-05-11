"""
Heuristics for comparing attribute instances.
"""

# standard library imports
from itertools import product
from difflib import SequenceMatcher
from utils import CliquerGraph

MAX_GRAPH_COMP_SIZE = 120
MINIMUM_NODE_WEIGHT = 0.75


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


class GraphSimilarity(Heuristic):
    def __init__(self, edges_1, data_1, edges_2, data_2):
        self.edges_1 = edges_1
        self.data_1 = data_1

        self.edges_2 = edges_2
        self.data_2 = data_2

    def ratio(self):
        if self.edges_are_equal():
            if self.data_is_equal():
                return 1.0
            else:
                return self.data_similarity()
        else:
            return self.graph_similarity()

    def data_is_equal(self):
        return (self.data_1 == self.data_2)

    def edges_are_equal(self):
        #return (self.edges_1 == self.edges_2)
        return False

    def data_similarity(self):
        f_sum = 0
        d_sum = 0
        for block_num in range(len(self.data_1)):
            data_1 = self.data_1[block_num]
            data_2 = self.data_2[block_num]
            ratio = SequenceMatcher(a=data_1, b=data_2).ratio()

            len_1 = float(len(data_1))
            len_2 = float(len(data_2))

            f_sum += (len_1 + len_2)
            d_sum += (len_1 + len_2) * ratio
        return d_sum / f_sum

    def graph_similarity(self):
        nodes = product(range(len(self.data_1)), range(len(self.data_2)))

        filtered_nodes = []
        filtered_weights = []
        for node in nodes:
            weight = SequenceMatcher(a=self.data_1[node[0]],
                                     b=self.data_2[node[1]]).ratio()
            if weight > MINIMUM_NODE_WEIGHT:
                filtered_nodes.append(node)
                filtered_weights.append(int(weight * 1000))

        num_of_nodes = len(filtered_nodes)
        graph = CliquerGraph(num_of_nodes)

        for node_num in range(num_of_nodes):
            graph.set_vertex_weight(node_num, filtered_weights[node_num])

        for x in range(num_of_nodes):
            for y in range(num_of_nodes):
                (i, s) = filtered_nodes[x]
                (j, t) = filtered_nodes[y]
                if s != t and i != j:
                    if ((((i, j) in self.data_1) and
                         ((s, t) in self.data_2)) or
                        (((i, j) not in self.data_1) and
                         ((s, t) not in self.data_2))):
                        graph.add_edge(x, y)

        size = float(graph.clique_max_size())
        return size / (len(self.data_1) + len(self.data_2) - size)
