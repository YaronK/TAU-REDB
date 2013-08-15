"""
Django models representing functions and descriptions.
"""
# related third party imports
from django.db import models

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
    # TODO: un-comment?
    # num_of_imms = models.PositiveSmallIntegerField()
    num_of_insns = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    func_name = models.TextField()
    exe_name = models.TextField()

    def __unicode__(self):
        return "signature: " + self.signature


class String(models.Model):
    value = models.TextField(unique=True)

    def __unicode__(self):
        return self.value


class Call(models.Model):
    name = models.CharField(max_length=MAX_CALL_NAME_LENGTH,
                            unique=True)

    def __unicode__(self):
        return self.name


class Graph(models.Model):
    edges = models.TextField()
    blocks_bounds = models.TextField() 
    num_of_blocks = models.PositiveIntegerField()
    num_of_edges = models.PositiveIntegerField()
    function = models.OneToOneField(Function)

    def __unicode__(self):
        return str(self.id)

class Block(models.Model):
    graph = models.ForeignKey(Graph)
    dist_from_root = models.PositiveIntegerField()
    
    def __unicode__(self):
        return str(self.id)

class Instruction(models.Model):
    block = models.ForeignKey(Block)
    itype = models.PositiveSmallIntegerField()
    offset = models.PositiveIntegerField()
    immediate = models.PositiveIntegerField(blank=True, null=True)
    string = models.ForeignKey(to=String, blank=True, null=True)
    call = models.ForeignKey(to=Call, blank=True, null=True)

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



class User(models.Model):
    user_name = models.CharField(max_length=MAX_USER_NAME_LENGTH)
    password_hash = models.CharField(max_length=PASSWORD_DIGEST_SIZE_IN_BYTES)

    def __unicode__(self):
        return self.user_name


class Description(models.Model):
    function = models.ForeignKey(Function)
    user = models.ForeignKey(User)
    data = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return ("function: " + unicode(self.function) +
                ", user: " + unicode(self.user))
