"""
Django models representing functions and descriptions.
"""
# related third party imports
from django.db import models
from django.contrib.auth.models import User
import networkx as nx
import json
from django.utils.encoding import smart_text
import utils
from difflib import SequenceMatcher as SM
import constants

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
        self.signature = smart_text(func_signature)
        self.args_size = args_size
        self.vars_size = vars_size
        self.regs_size = regs_size
        self.frame_size = frame_size
        self.num_of_strings = num_of_strings
        self.num_of_calls = num_of_calls
        self.num_of_imms = num_of_imms
        self.num_of_insns = num_of_insns
        self.func_name = smart_text(func_name)
        self.exe_name = smart_text(exe_name)

        self.instructions = []

        for offset in range(len(itypes)):
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

        self.graph = Graph()
        self.graph.initialize(block_bounds, edges, self)
        self.executable = Executable()
        self.executable.initialize(exe_signature, self, exe_name)

    def get_data(self):
        pass

    def save(self, *args, **kwargs):
        super(Function, self).save(*args, **kwargs)
        self.graph.function = self
        self.graph.distances = json.dumps(self.graph.distances,
                                          encoding='ISO-8859-1')
        self.graph.save()
        self.executable.save()

        for instruction in self.instructions:
            instruction.function = self
            if instruction.string is not None:
                instruction.string, _ = String.objects.\
                    get_or_create(value=instruction.string.value)

            if instruction.call is not None:
                instruction.call, _ = \
                    Call.objects.get_or_create(name=instruction.call.name)

        chunks = [self.instructions[x:x + 100]
                  for x in xrange(0, len(self.instructions), 100)]
        for chunk in chunks:
            Instruction.objects.bulk_create(chunk)

    def __unicode__(self):
        return self.exe_name + u": " + self.func_name


class String(models.Model):
    value = models.TextField(unique=True)

    class ComparableString(unicode):
        def __hash__(self):
            return 0

        def __eq__(self, other):
            return (type(self) == type(other) and
                    (SM(a=self, b=other).ratio() > self.flexibility))

        def set_flexibility(self, flexibility):
            self.flexibility = flexibility

    def initialize(self, value):
        self.value = smart_text(value)

    def get_data(self):
        comparable_string = String.ComparableString(self.value)
        flexibility = constants.block_similarity.STRING_VALUE_FLEXIBILITY
        comparable_string.set_flexibility(flexibility)
        return comparable_string

    def __unicode__(self):
        return self.value


class Call(models.Model):
    name = models.CharField(max_length=MAX_CALL_NAME_LENGTH,
                            unique=True)

    class ComparableCall(unicode):
        def __hash__(self):
            return 0

        def __eq__(self, other):
            return (type(self) == type(other) and
                    (SM(a=self, b=other).ratio() > self.flexibility))

        def set_flexibility(self, flexibility):
            self.flexibility = flexibility

    def initialize(self, name):
        self.name = smart_text(name)

    def get_data(self):
        comparable_call = Call.ComparableCall(self.name)
        flexibility = constants.block_similarity.CALL_NAME_FLEXIBILITY
        comparable_call.set_flexibility(flexibility)
        return comparable_call

    def __unicode__(self):
        return self.name


class Graph(models.Model):
    edges = models.TextField()
    num_of_blocks = models.PositiveIntegerField()
    num_of_edges = models.PositiveIntegerField()
    block_bounds = models.TextField()
    distances = models.TextField()
    function = models.ForeignKey(Function)

    def initialize(self, block_bounds, edges, function):

        self.edges = edges
        self.num_of_blocks = len(block_bounds)
        self.num_of_edges = len(edges)
        self.function = function

        self.block_bounds = block_bounds
        self.nx_graph = self._get_nx_graph()
        self.distances = self._get_distances()
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
        # TODO: add list
        for i in range(self.num_of_blocks):
            nx_g.add_node(i)
        for (x, y) in self.edges:
            nx_g.add_edge(x, y)

        return nx_g

    def _get_distances(self):
        return nx.single_source_dijkstra_path_length(self.nx_graph, 0)

    def _get_blocks(self):
        if self.pk:
            instructions = self.function.instruction_set.all()
            self.block_bounds = json.loads(self.block_bounds)
            self.distances = json.loads(self.distances,
                                        object_hook=utils._decode_dict)
        else:
            instructions = self.function.instructions

        ins_data = [instruction.get_data() for instruction in instructions]
        blocks = []
        for block_id in range(self.num_of_blocks):
            data = {}
            bounds = self.block_bounds[block_id]
            start_offset = bounds[0]
            end_offset = bounds[1] + 1
            ins_data_in_block = ins_data[start_offset:end_offset]
            if self.pk:
                block_id = str(block_id)
            if block_id in self.distances:  # reachable from root
                data["dist_from_root"] = self.distances[block_id]
            else:
                data["dist_from_root"] = -1

            data["block_data"] = []
            for ins in ins_data_in_block:
                data["block_data"].append(ins["itype"])
                if ins["string"] is not None:
                    data["block_data"].append(ins["string"])
                if ins["call"] is not None:
                    data["block_data"].append(ins["call"])
                if ins["imm"] is not None:
                    data["block_data"].append(ins["imm"])
            blocks.append(data)
        return blocks

    def _attach_data_to_nx_graph(self):
        blocks = self._get_blocks()
        for i in range(self.num_of_blocks):
            self.nx_graph.node[i]['data'] = blocks[i]

    def __unicode__(self):
        return unicode(self.function) + u"'s graph"


class ComparableImmediate(long):
    def __eq__(self, other):
        return type(self) == type(other) and long(self) == long(other)


class ComparableItype(int):
    def __eq__(self, other):
        return type(self) == type(other) and int(self) == int(other)


class Instruction(models.Model):
    function = models.ForeignKey(Function)
    itype = models.PositiveSmallIntegerField()
    offset = models.PositiveIntegerField()
    immediate = models.PositiveIntegerField(blank=True, null=True)
    string = models.ForeignKey(to=String, blank=True, null=True)
    call = models.ForeignKey(to=Call, blank=True, null=True)

    def initialize(self, function, itype, offset, immediate=None, string=None,
                   call=None):
        self.itype = itype
        self.offset = offset
        self.function = function
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
        tmp_data["itype"] = ComparableItype(self.itype)

        tmp_data["string"] = self.string.get_data() if self.string else None
        tmp_data["call"] = self.call.get_data() if self.call else None
        tmp_data["imm"] = (ComparableImmediate(self.immediate) if
                           self.immediate else None)
        return tmp_data

    def __unicode__(self):
        res = (u"function: " + unicode(self.function) +
               u", offset: " + unicode(self.offset) +
               u", itype: " + unicode(self.itype))
        if self.immediate is not None:
            res += u", immediate: " + unicode(self.immediate)
        if self.string is not None:
            res += u", string: " + unicode(self.string)
        if self.call is not None:
            res += u", call: " + unicode(self.call)
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
        self.exe_name = smart_text(exe_name)

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
        return self.names


class Description(models.Model):
    function = models.ForeignKey(Function)
    user = models.ForeignKey(User)
    data = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def initialize(self, function, data, user):
        self.function = function
        self.data = smart_text(data)
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
