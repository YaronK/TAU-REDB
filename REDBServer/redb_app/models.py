"""
Django models representing functions and descriptions.
"""
# related third party imports
from django.db import models
from django.contrib.auth.models import User
import networkx as nx
import redb_app
import json

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

    def initialize(self, func_signature, exe_signature, args_size, vars_size,
                   regs_size, frame_size, num_of_strings, num_of_calls,
                   num_of_imms, num_of_insns, func_name, exe_name, immediates,
                   strings, itypes, calls, block_bounds, edges):
        self.signature = func_signature
        self.args_size = args_size
        self.vars_size = vars_size
        self.regs_size = regs_size
        self.frame_size = frame_size
        self.num_of_strings = num_of_strings
        self.num_of_calls = num_of_calls
        self.num_of_imms = num_of_imms
        self.num_of_insns = num_of_insns
        self.func_name = func_name
        self.exe_name = exe_name

        self.graph = Graph()

        self.graph.initialize(immediates, strings, itypes, calls, block_bounds,
                              edges, self)

        self.executable = Executable()
        self.executable.initialize(exe_signature, self, exe_name)

    def get_data(self):
        pass

    def save(self, *args, **kwargs):
        super(Function, self).save(*args, **kwargs)
        self.graph.function = self
        self.graph.save()
        self.executable.save()

    def __unicode__(self):
        return self.exe_name + ":" + self.func_name


class String(models.Model):
    value = models.TextField(unique=True)

    def initialize(self, value):
        self.value = value

    def get_data(self):
        return self.value

    def save(self, *args, **kwargs):
        super(String, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.value


class Call(models.Model):
    name = models.CharField(max_length=MAX_CALL_NAME_LENGTH,
                            unique=True)

    def initialize(self, name):
        self.name = name

    def get_data(self):
        return self.name

    def save(self, *args, **kwargs):
        super(Call, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.name


class Graph(models.Model):
    edges = models.TextField()
    num_of_blocks = models.PositiveIntegerField()
    num_of_edges = models.PositiveIntegerField()
    function = models.ForeignKey(Function)

    def initialize(self, immediates, strings, itypes, calls, block_bounds,
                 edges, function):

        self.edges = edges
        self.num_of_blocks = len(block_bounds)
        self.num_of_edges = len(edges)
        self.function = function
        self.nx_graph = self._get_nx_graph()
        self.distances = self._get_distances()
        self.blocks = []
        for block_id in range(self.num_of_blocks):
            bounds = block_bounds[block_id]
            if block_id in self.distances:  # reachable from root
                distance = self.distances[block_id]
            else:
                distance = -1
            block = Block()
            block.initialize(immediates, strings, itypes, calls, bounds,
                             distance, self)
            self.blocks.append(block)
        self._attach_data_to_nx_graph()

    def get_data(self):
        if hasattr(self, "nx_graph"):
            return self.nx_graph
        if self.pk:  # graph is already saved in the db
            self.nx_graph = self._get_nx_graph()
            self._attach_data_to_nx_graph()
        return self.nx_graph

    def _get_nx_graph(self):
        if self.pk:
            self.edges = json.loads(self.edges)
        nx_g = nx.DiGraph()
        for i in range(self.num_of_blocks):
            nx_g.add_node(i)
        for (x, y) in self.edges:
            nx_g.add_edge(x, y)

        return nx_g

    def _get_distances(self):
        return nx.single_source_dijkstra_path_length(self.nx_graph, 0)

    def _attach_data_to_nx_graph(self):

        if self.pk:
            blocks = self.block_set.all()
        else:
            blocks = self.blocks
        for i in range(self.num_of_blocks):
            self.nx_graph.node[i]['data'] = blocks[i].get_data()

    def save(self, *args, **kwargs):
        super(Graph, self).save(*args, **kwargs)

        for block in self.blocks:
            block.graph = self
            block.save()

    def __unicode__(self):
        return str(self.id)


class Block(models.Model):
    graph = models.ForeignKey(Graph)
    dist_from_root = models.PositiveIntegerField()

    def initialize(self, immediates, strings, itypes, calls, bounds, distance,
                 graph):
        self.graph = graph
        self.dist_from_root = distance

        start_offset = bounds[0]
        end_offset = bounds[1] + 1

        self.instructions = []

        for offset in range(start_offset, end_offset):
            str_offset = str(offset)

            immediate = None
            if str_offset in immediates:
                immediate = immediates[str_offset]

            string = None
            if str_offset in strings:
                string = strings[str_offset]

            call = None
            if str_offset in calls:
                call = calls[str_offset]

            instruction = Instruction()
            instruction.initialize(self, itypes[offset], offset, immediate,
                                   string, call)
            self.instructions.append(instruction)

    def get_data(self):

        if self.pk:  # extracting data from DB
            instructions = self.instruction_set.all()
        else:
            instructions = self.instructions

        none_filter = lambda x: x is not None

        ins_data = [instruction.get_data() for instruction in instructions]

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

        return tmp_data

    def save(self, *args, **kwargs):
        super(Block, self).save(*args, **kwargs)
        for instruction in self.instructions:
            instruction.block = self
            instruction.save()
        """
        chunks = [self.instructions[x:x + 100]
                  for x in xrange(0, len(self.instructions), 100)]
        for chunk in chunks:
            Instruction.objects.bulk_create(chunk)
        """
    def __unicode__(self):
        return unicode(self.graph.function)


class Instruction(models.Model):
    block = models.ForeignKey(Block)
    itype = models.PositiveSmallIntegerField()
    offset = models.PositiveIntegerField()
    immediate = models.PositiveIntegerField(blank=True, null=True)
    string = models.ForeignKey(to=String, blank=True, null=True)
    call = models.ForeignKey(to=Call, blank=True, null=True)

    def initialize(self, block, itype, offset, immediate=None, string=None,
                   call=None):
        self.itype = itype
        self.offset = offset
        self.block = block
        self.immediate = immediate
        if string is not None:
            self.string = String()
            self.string.initialize(string)
        else:
            self.string = None
        if call is not None:
            self.call = Call()
            self.call.initialize(call)
        else:
            self.call = None

    def get_data(self):
        tmp_data = {}
        tmp_data["itype"] = self.itype
        if self.string is not None:
            tmp_data["string"] = self.string.get_data()
        else:
            tmp_data["string"] = None
        if self.call is not None:
            tmp_data["call"] = self.call.get_data()
        else:
            tmp_data["call"] = None
        tmp_data["imm"] = self.immediate
        return tmp_data

    def save(self, *args, **kwargs):
        if self.string is not None:
            try:
                self.string = String.objects.get(value=self.string.value)
            except String.DoesNotExist:
                self.string.save()
                self.string = self.string
        if self.call is not None:
            try:
                self.call = Call.objects.get(name=self.call.name)
            except Call.DoesNotExist:
                self.call.save()
                self.call = self.call
        super(Instruction, self).save(*args, **kwargs)

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
                                 unique=True)
    functions = models.ManyToManyField(Function)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    names = models.TextField()

    def initialize(self, signature, function, exe_name):
        self.signature = signature
        self.function = function
        self.exe_name = exe_name

    def get_data(self):
        pass

    def save(self, *args, **kwargs):
        try:  # exe already exists
            exe = Executable.objects.get(signature=self.signature)
            self.function = self.function
            exe.functions.add(self.function)
            if self.exe_name not in exe.names:
                exe.names += self.exe_name + ", "
            super(Executable, exe).save(*args, **kwargs)
        except Executable.DoesNotExist:
            self.names = self.exe_name
            super(Executable, self).save(*args, **kwargs)
            self.function = self.function
            self.functions.add(self.function)

    def __unicode__(self):
        return "signature: " + self.signature


class Description(models.Model):
    function = models.ForeignKey(Function)
    user = models.ForeignKey(User)
    data = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def initialize(self, function, data, user):
        self.function = function
        self.data = data
        self.user = user

    def get_data(self):
        pass

    def save(self, *args, **kwargs):
        try:  # we already have this description for this function
            desc = self.function.description_set.get(data=self.data)
        except Description.DoesNotExist:
            try:  # we already have a description for this user and function
                desc = self.function.description_set.get(user=self.user)
                desc.data = self.data
                super(Description, desc).save(*args, **kwargs)
            except Description.DoesNotExist:
                super(Description, self).save(*args, **kwargs)

    def __unicode__(self):
        return ("function: " + unicode(self.function) +
                ", user: " + unicode(self.user))
