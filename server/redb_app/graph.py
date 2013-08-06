

class Block:
    def __init__(self, itypes, strings, calls, immediates, dist_from_root):
        self.itypes = itypes
        self.strings = ""
        for string in strings:
            self.strings += string

        self.calls = ""
        for call in calls:
            self.calls += str(call)
        self.immediates = immediates
        self.dist_from_root = dist_from_root

    def __eq__(self, other):
        return ((self.itypes == other.itypes) and
                (self.strings == other.strings) and
                (self.calls == other.calls) and
                (self.immediates == other.immediates) and
                (self.dist_from_root == other.dist_from_root))

    def similar(self, other):
        pass


class Graph:
    def __init__(self, blocks, edges):
        self.blocks = blocks
        self.edges = edges

    def __eq__(self, other):
        return (self.edges == other.edges and self.blocks == other.blocks)
