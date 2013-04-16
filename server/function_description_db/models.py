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


class String(models.Model):
    value = models.TextField()

    def __unicode__(self):
        return str(self.id)


class LibraryCall(models.Model):
    name = models.CharField(max_length=MAX_LIB_CALL_NAME_LENGTH)

    def __unicode__(self):
        return str(self.id)


class Executable(models.Model):
    signature = models.CharField(max_length=EXE_DIGEST_SIZE_IN_BYTES)

    def __unicode__(self):
        return str(self.id)


class Function(models.Model):
    first_addr = models.PositiveIntegerField()
    signature = models.CharField(max_length=FUNC_DIGEST_SIZE_IN_BYTES)
    num_of_args = models.PositiveIntegerField()
    num_of_vars = models.PositiveIntegerField()
    executable = models.ManyToManyField(Executable)

    def __unicode__(self):
        return str(self.id)


class Graph(models.Model):
    edges = models.TextField()
    blocks_data = models.TextField()
    num_of_blocks = models.PositiveIntegerField()
    num_of_edges = models.PositiveIntegerField()
    function = models.OneToOneField(Function)

    def __unicode__(self):
        return str(self.id)


class Instruction(models.Model):
    itype = models.PositiveSmallIntegerField()
    offset = models.PositiveIntegerField()
    function = models.ForeignKey(Function)
    string = models.ForeignKey(String, blank=True, null=True)
    library_call = models.ForeignKey(LibraryCall, blank=True, null=True)

    def __unicode__(self):
        return str(self.id)


class User(models.Model):
    user_name = models.CharField(max_length=MAX_USER_NAME_LENGTH)
    password_hash = models.CharField(max_length=PASSWORD_DIGEST_SIZE_IN_BYTES)

    def __unicode__(self):
        return str(self.id)


class Description(models.Model):
    function = models.ForeignKey(Function)
    user = models.ForeignKey(User)
    data = models.TextField()

    def __unicode__(self):
        return str(self.id)
