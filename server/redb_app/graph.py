

class Block:
    def __init__(self, itypes, strings, calls, immediates):
        self.itypes = itypes
        self.strings = ""
        for string in strings:
            self.strings += str(string)

        self.calls = ""
        for call in calls:
            self.calls += str(call)
        self.immediates = immediates

    def __eq__(self, other):
        return ((self.itypes == other.itypes) and
                (self.strings == other.strings) and
                (self.calls == other.calls) and
                (self.immediates == other.immediates))

    def similar(self, other):
        pass


class Graph:
    def __init__(self, blocks, edges):
        self.blocks = blocks
        self.edges = edges

    def __eq__(self, other):
        return (self.edges == other.edges and self.blocks == other.blocks)
