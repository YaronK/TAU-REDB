"""
Django models representing functions and descriptions.
"""
# related third party imports
from django.db import models
from django.contrib.auth.models import User
import networkx as nx

MAX_EXE_NAME_LENGTH = 255
EXE_DIGEST_SIZE_IN_BYTES = 32
FUNC_DIGEST_SIZE_IN_BYTES = 32
PASSWORD_DIGEST_SIZE_IN_BYTES = 32
MAX_CALL_NAME_LENGTH = 100
MAX_USER_NAME_LENGTH = 25
MAX_VAR_NAME_LENGTH = 25


class Function(models.Model):
    signature = models.CharField(max_length=FUNC_DIGEST_SIZE_IN_BYTES,
                                 unique=True)
    args_size = models.PositiveIntegerField()
    vars_size = models.PositiveIntegerField()
    regs_size = models.PositiveIntegerField()
    frame_size = models.PositiveIntegerField()
    num_of_strings = models.PositiveSmallIntegerField()  # Counting duplicates
    num_of_calls = \
        models.PositiveSmallIntegerField()  # Counting duplicates
    num_of_imms = models.PositiveSmallIntegerField()
    num_of_insns = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    func_name = models.TextField()
    exe_name = models.TextField()

    def __unicode__(self):
        return self.exe_name + ":" + self.func_name


class String(models.Model):
    value = models.TextField(unique=True)

    def data(self):
        return self.value

    def __unicode__(self):
        return self.value


class Call(models.Model):
    name = models.CharField(max_length=MAX_CALL_NAME_LENGTH,
                            unique=True)

    def data(self):
        return self.name

    def __unicode__(self):
        return self.name


class Graph(models.Model):
    edges = models.TextField()
    num_of_blocks = models.PositiveIntegerField()
    num_of_edges = models.PositiveIntegerField()

    function = models.OneToOneField(Function)

    def get_nx_graph(self):
        if not hasattr(self, "nx_g"):
            self.nx_g = nx.DiGraph()
            blocks = self.block_set.all()
            for i in range(len(blocks)):
                self.nx_g.add_node(i, {"block_data": blocks[i].data()})

            for (x, y) in self.edges:
                self.nx_g.add_edge(x, y)

        return self.nx_g

    def get_distances(self):
        if not hasattr(self, "distances"):
            self.distances = \
                nx.single_source_dijkstra_path_length(self.get_nx_graph(), 0)

        return self.distances

    def __unicode__(self):
        return str(self.id)


class Block(models.Model):
    graph = models.ForeignKey(Graph)
    dist_from_root = models.PositiveIntegerField()
    block_id = models.PositiveIntegerField()

    def data(self):
        if hasattr(self, "tmp_data"):
            return self.tmp_data

        none_filter = lambda x: x is not None

        ins_data = [instruction.data() for instruction in
                    self.instruction_set.all()]

        tmp_data = {}

        tmp_data["itypes"] = [ins["itype"] for ins in ins_data]

        string_list = filter(none_filter,
                             [ins["string"] for ins in ins_data])
        tmp_data["strings"] = ''.join(string_list)

        calls_list = filter(none_filter,
                            [ins["call"] for ins in ins_data])
        tmp_data["calls"] = ''.join(calls_list)

        tmp_data["imms"] = filter(none_filter,
                                  [ins["imm"] for ins in ins_data])

        tmp_data["dist_from_root"] = self.dist_from_root

        self.tmp_data = tmp_data

        return tmp_data

    def __eq__(self, other):
        my_data = self.data()
        other_data = other.data()
        return ((my_data.itypes == other_data.itypes) and
                (my_data.strings == other_data.strings) and
                (my_data.calls == other_data.calls) and
                (my_data.immediates == other_data.immediates) and
                (my_data.dist_from_root == other_data.dist_from_root))

    def __unicode__(self):
        return unicode(self.graph.function) + " : " + str(self.block_id)


class Instruction(models.Model):
    block = models.ForeignKey(Block)
    itype = models.PositiveSmallIntegerField()
    offset = models.PositiveIntegerField()
    immediate = models.PositiveIntegerField(blank=True, null=True)
    string = models.ForeignKey(to=String, blank=True, null=True)
    call = models.ForeignKey(to=Call, blank=True, null=True)

    def data(self):
        tmp_data = {}
        tmp_data["itype"] = self.itype
        tmp_data["string"] = self.string.data()
        tmp_data["call"] = self.call.data()
        tmp_data["imm"] = self.immediate
        return tmp_data

    def __unicode__(self):
        res = ("block: " + unicode(self.block) +
               ", offset: " + str(self.offset) +
               ", itype: " + str(self.itype))
        if self.immediate is not None:
            res += ", immediate: " + str(self.immediate)
        if self.string is not None:
            res += ", string: " + unicode(self.string)
        if self.call is not None:
            res += ", call: " + unicode(self.call)
        return res


class Executable(models.Model):
    signature = models.CharField(max_length=EXE_DIGEST_SIZE_IN_BYTES,
                                 unique=True, primary_key=True)
    functions = models.ManyToManyField(Function)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    names = models.TextField()

    def __unicode__(self):
        return "signature: " + self.signature


class Description(models.Model):
    function = models.ForeignKey(Function)
    user = models.ForeignKey(User)
    data = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return ("function: " + unicode(self.function) +
                ", user: " + unicode(self.user))
