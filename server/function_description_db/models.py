"""
Django models representing functions and descriptions.
"""
# related third party imports
from django.db import models

MAX_EXE_NAME_LENGTH = 255
EXE_DIGEST_SIZE_IN_BYTES = 32
FUNC_DIGEST_SIZE_IN_BYTES = 32
PASSWORD_DIGEST_SIZE_IN_BYTES = 32
MAX_LIB_CALL_NAME_LENGTH = 100
MAX_USER_NAME_LENGTH = 25
MAX_VAR_NAME_LENGTH = 25


class Function(models.Model):
    signature = models.CharField(max_length=FUNC_DIGEST_SIZE_IN_BYTES,
                                 unique=True, primary_key=True)
    args_size = models.PositiveIntegerField()
    vars_size = models.PositiveIntegerField()
    regs_size = models.PositiveIntegerField()
    frame_size = models.PositiveIntegerField()
    num_of_strings = models.PositiveSmallIntegerField()  # Counting duplicates
    num_of_lib_calls = \
        models.PositiveSmallIntegerField()  # Counting duplicates
    # num_of_imms = models.PositiveSmallIntegerField()

    def __unicode__(self):
        return "signature: " + self.signature


class String(models.Model):
    value = models.TextField(unique=True, primary_key=True)

    def __unicode__(self):
        return self.value


class LibraryCall(models.Model):
    name = models.CharField(max_length=MAX_LIB_CALL_NAME_LENGTH,
                            unique=True, primary_key=True)

    def __unicode__(self):
        return self.name


class Instruction(models.Model):
    function = models.ForeignKey(Function)
    itype = models.PositiveSmallIntegerField()
    offset = models.PositiveIntegerField()

    immediate = models.PositiveIntegerField(blank=True, null=True)
    string = models.ForeignKey(to=String, blank=True, null=True)
    lib_call = models.ForeignKey(to=LibraryCall, blank=True, null=True)

    def __unicode__(self):
        res = ("function: " + unicode(self.function) +
               ", offset: " + str(self.offset) +
               ", itype: " + str(self.itype))
        if self.immediate is not None:
            res += ", immediate: " + str(self.immediate)
        if self.string is not None:
            res += ", string: " + unicode(self.string)
        if self.lib_call is not None:
            res += ", lib_call: " + unicode(self.lib_call)
        return res


class Executable(models.Model):
    signature = models.CharField(max_length=EXE_DIGEST_SIZE_IN_BYTES,
                                 unique=True, primary_key=True)
    functions = models.ManyToManyField(Function)

    def __unicode__(self):
        return "signature: " + self.signature


class Graph(models.Model):
    edges = models.TextField()
    blocks_data = models.TextField()
    num_of_blocks = models.PositiveIntegerField()
    num_of_edges = models.PositiveIntegerField()
    function = models.OneToOneField(Function)

    def __unicode__(self):
        return str(self.id)


class User(models.Model):
    user_name = models.CharField(max_length=MAX_USER_NAME_LENGTH)
    password_hash = models.CharField(max_length=PASSWORD_DIGEST_SIZE_IN_BYTES)

    def __unicode__(self):
        return self.user_name


class Description(models.Model):
    function = models.ForeignKey(Function)
    user = models.ForeignKey(User)
    data = models.TextField()

    def __unicode__(self):
        return ("function: " + unicode(self.function) +
                ", user: " + unicode(self.user))
