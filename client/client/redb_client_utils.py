"""
Utilities for all the other modules.
"""

# standard library imports
import os
import shutil
import traceback
import functools
import httplib
import mimetypes
import mimetools
import ConfigParser
import string
import json

# related third party imports
import idc
import idautils
import idaapi

# Constants
PLUGIN_DIR_PATH = os.path.dirname(__file__)
CONFIG_FILE_PATH = os.path.join(PLUGIN_DIR_PATH, 'IdaProject.INI')


#==============================================================================
# Plugin configuration
#==============================================================================
class PluginConfig:
    """
    Configuration management.
    """
    def __init__(self):
        self._path = CONFIG_FILE_PATH

    def get_current_from_ini_file(self):
        parser = ConfigParser.SafeConfigParser()
        parser.read(self._path)

        self.host = parser.get('REDB', 'host')
        self.username = parser.get('REDB', 'username')
        self.pass_hash = parser.get('REDB', 'pass_hash')

    def change_config(self):
        try:
            self.get_current_from_ini_file()
        except:
            self.host = "<ip>:<port>"
            self.username = "Username"
            self.pass_hash = "Password"

        os.remove(self._path)
        cfgfile = open(self._path, 'w')
        parser = ConfigParser.SafeConfigParser()
        parser.add_section('REDB')

        host = \
            _getUserConfigInput(self.host,
                                "REDB: Please enter the server's ip and port:")
        parser.set('REDB', 'host', host)

        username = \
            _getUserConfigInput(self.username,
                                "REDB: Enter your username:")
        parser.set('REDB', 'username', username)

        pass_hash = \
            _getUserConfigInput(self.pass_hash,
                                "REDB: Enter your password:")
        parser.set('REDB', 'pass_hash', pass_hash)

        # writing configurations to file
        parser.write(cfgfile)
        cfgfile.close()


def _getUserConfigInput(defval, prompt):
    configInput = None
    while configInput is None:
        try:
            configInput = idc.AskStr(defval, prompt)
        except:
            pass
    return configInput


def _parse_config_file():
    """
    Checking user configurations exist upon plugin initialization.
    """
    parse_config = PluginConfig()
    try:
        parse_config.get_current_from_ini_file()
    except:
        parse_config.change_config()

    return parse_config


#==============================================================================
# Description and Tag utilities
#==============================================================================
class DescriptionUtils:
    @classmethod
    def get_all(cls, start_addr):
        dic = {}
        dic["func_name"] = cls.get_func_name(start_addr)
        dic["comments"] = cls.get_all_comments(start_addr)
        dic["func_comments"] = cls.get_both_func_comments(start_addr)
        dic["stack_members"] = cls.get_stack_members(start_addr)
        return dic

    @classmethod
    def get_func_name(cls, start_addr):
        return idc.GetFunctionName(start_addr)

    @classmethod
    def get_all_comments(cls, start_addr):
        comments = cls.get_comments(start_addr, 0)
        comments += cls.get_comments(start_addr, 1)
        return comments

    @classmethod
    def get_comments(cls, start_addr, repeatable):
        return filter(None,
            [cls.get_one_comment(ea, start_addr, repeatable)
             for ea in idautils.FuncItems(start_addr)])

    @classmethod
    def get_one_comment_tuple(cls, real_ea, start_addr, repeatable):
        """
        Returns a tuple (offset, is-repeatable, string).
        If it does not exist returns None.
        """
        string = cls.get_one_comment(real_ea, repeatable)
        if string:
            return (real_ea - start_addr, repeatable, string)
        else:
            return None

    @classmethod
    def get_one_comment(cls, real_ea, repeatable):
        return idc.GetCommentEx(real_ea, repeatable)

    @classmethod
    def get_both_func_comments(cls, start_addr):
        comments = cls.get_func_comment(start_addr, 0)
        if comments:
            return (comments +
                    cls.get_func_comment(start_addr, 1))
        else:
            return cls.get_func_comment(start_addr, 1)

    @classmethod
    def get_func_comment(cls, start_addr, repeatable):
        """
        Returns a tuple (is-repeatable, string).
        If it does not exist returns None.
        """
        reg_cmt = idc.GetFunctionCmt(start_addr, repeatable)
        if reg_cmt:
            return (repeatable, reg_cmt)
        else:
            return None

    @classmethod
    def get_stack_members(cls, start_addr):
        """
        Generates and returns a list of stack members (variables and
        arguments).
        member := (offset in stack, name, size, flag, regular comment,
        repeatable comment)
        Excludes ' r' and ' s'.
        """
        stack = idc.GetFrame(start_addr)
        stack_size = idc.GetStrucSize(stack)
        name_set = set(idc.GetMemberName(stack, i) for i in xrange(stack_size))
        name_set -= set([' r', ' s', None])
        offset_set = set(idc.GetMemberOffset(stack, name) for name in name_set)
        member_get_data =\
            lambda offset: (offset,
                            idc.GetMemberName(stack, offset),
                            idc.GetMemberSize(stack, offset),
                            idc.GetMemberFlag(stack, offset),
                            idc.GetMemberComment(stack, offset, 0),
                            idc.GetMemberComment(stack, offset, 1))
        return map(member_get_data, offset_set)

    @classmethod
    def set_all(cls, start_addr, description_dict, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        func_name = description_dict["func_name"]
        comments = description_dict["comments"]
        func_comments = description_dict["func_comments"]
        stack_members = description_dict["stack_members"]

        if append is None:
            cls.remove_all_comments(start_addr)

        cls.set_func_name(start_addr, func_name)
        cls.set_stack_members(start_addr, stack_members)

        cls.set_comments(start_addr, comments, append)
        cls.set_both_func_comments(start_addr, func_comments, append)
        idaapi.refresh_idaview_anyway()

    @classmethod
    def set_func_name(cls, start_addr, func_name):
        idaapi.set_name(start_addr, func_name, idaapi.SN_NOWARN)

    @classmethod
    def set_stack_members(cls, start_addr, stack_members):
        """
        Setting member attributes should be done in a more delicate manner:
        Only set name and comment if member exists (same size, flags).
        We currently do not create new members.
        assumes member structure defined at GetStackMembers().
        """
        stack = idc.GetFrame(start_addr)
        member_filter_lambda =\
            lambda member: ((idc.GetMemberFlag(stack, member[0]) == member[3])
                            and
                            (idc.GetMemberSize(stack, member[0]) == member[2]))

        filtered_member_set = filter(member_filter_lambda, stack_members)

        member_set_data_lambda =\
            lambda member: (idc.SetMemberName(stack, member[0], member[1]),
                            idc.SetMemberComment(stack, member[0], 0,
                                                 member[4]),
                            idc.SetMemberComment(stack, member[0], 1,
                                                 member[5]))

        map(member_set_data_lambda, filtered_member_set)

    @classmethod
    def set_comments(cls, start_addr, comments, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        for (offset, repeatable, text) in comments:
            real_ea = start_addr + offset
            cls.set_one_comment(real_ea, text, repeatable, append)

    @classmethod
    def set_one_comment(cls, real_ea, text, repeatable, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        cur_comment = cls.get_one_comment(real_ea, repeatable)
        if append == True and cur_comment:
            text = cur_comment + "; " + text
        elif append == False and cur_comment:
            text += "; " + cur_comment
        if repeatable:
            idc.MakeRptCmt(real_ea, text)
        else:
            idc.MakeComm(real_ea, text)

    @classmethod
    def set_both_func_comments(cls, start_addr, func_comments, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        for (repeatable, text) in func_comments:
            cls.set_func_comment(start_addr, append, repeatable, text)

    @classmethod
    def set_func_comment(cls, start_addr, repeatable, text, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        cur_comment = cls.get_func_comment(start_addr, repeatable)
        if append == True and cur_comment:
            text = cur_comment + "; " + text
        elif append == False and cur_comment:
            text += "; " + cur_comment
        idc.SetFunctionCmt(start_addr, text, repeatable)

    @classmethod
    def remove_all_comments(cls, start_addr):
        for ea in idautils.FuncItems(start_addr):
            cls.set_one_comment(ea, "", 0)
            cls.set_one_comment(ea, "", 1)
            cls.set_func_comment(start_addr, 0, "")
            cls.set_func_comment(start_addr, 1, "")


class Tag:
    """
    Adding a special tag in the "function comment".
    """
    def __init__(self, start_addr, text):
        self._start_addr = start_addr
        self._text = text

    def add_tag(self):
        DescriptionUtils.set_func_comment(self._start_addr, False, self._text,
                                          False)

    def remove_tag(self):
        cur_comment = DescriptionUtils.get_func_comment(self._start_addr, 0)
        if string.find(cur_comment, self._text) == 0:
            cur_comment = cur_comment[len(self._text):]
        DescriptionUtils.set_func_comment(self._start_addr, False, cur_comment,
                                          None)


#==============================================================================
# Changing from unicode for compatibility.
#==============================================================================
def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


#==============================================================================
# FuncAttributes Utilities
#==============================================================================
#-----------------------------------------------------------------------------
# Operands
#-----------------------------------------------------------------------------
def collect_operands_data(func_item):
    """
    Given an instruction address, returns operands as pairs of type and
    value.
    """
    operands_list = []
    for i in range(6):
        if idc.GetOpType(func_item, i) != 0:
            pair = (idc.GetOpType(func_item, i),
                    idc.GetOperandValue(func_item, i))
            operands_list.append(pair)
    return operands_list


#-----------------------------------------------------------------------------
# Imports and their functions.
#-----------------------------------------------------------------------------
class ImportsAndFunctions:
    def collect_imports_data(self):
        """
        Modules and their functions.
        """
        self._imported_modules = []
        nimps = idaapi.get_import_module_qty()  # number of imports

        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                print ("REDB: Failed to get_current_from_ini_file import" +
                       "module name for #%d" % i)
                continue
            module = _ImportModule(name)
            self._imported_modules.append(module)
            idaapi.enum_import_names(i, self._add_single_imported_function)
        return self._imported_modules

    def _add_single_imported_function(self, ea, name, ordinal):
        if not name:
            imported_function = _SingleImportedFunction(ea, ordinal)
        else:
            imported_function = _SingleImportedFunction(ea, ordinal, name)

        self._imported_modules[-1].improted_functions.append(imported_function)

        return True


class _SingleImportedFunction():
    """
    Represents an imported function.
    """
    def __init__(self, addr, ordinal, name='NoName'):
        self.ordinal = ordinal
        self.name = name
        self.addr = addr


class _ImportModule():
    """
    Represents an imported module.
    """
    def __init__(self, name):
        self.name = name
        self.improted_functions = []
        self._addresses = None

    def get_addresses(self):
        """
        Returns addresses of functions imported from this module.
        """
        if self._addresses == None:
            self._addresses = [imported_function.addr for imported_function in
                               self.improted_functions]
        return self._addresses


#-----------------------------------------------------------------------------
# Data
#-----------------------------------------------------------------------------
def instruction_data(func_item):
    """
    Returns an integer representing the instruction.
    """
    func_item_size = idautils.DecodeInstruction(func_item).size
    cmd_data = 0
    for i in idaapi.get_many_bytes(func_item, func_item_size):
        cmd_data = (cmd_data << 8) + ord(i)
    return cmd_data


#-----------------------------------------------------------------------------
# Additional general Utilities
#-----------------------------------------------------------------------------
def _backup_idb_file():
    """
    Creating a backup of the .idb, just in case.
    """
    try:
        idb_file_path = idc.GetIdbPath()
        backup_file_path = idb_file_path + ".backup"

        if os.path.exists(backup_file_path):
            os.remove(backup_file_path)

        shutil.copy2(idb_file_path, backup_file_path)
        print "REDB: A backup of the .idb file was created."
    except:
        print "REDB: Failed to backup the .idb file."


def _create_callback_func_table():
    ida_plugins_dir = idaapi.idadir("plugins")
    ida_plugins_cfg_path = os.path.join(ida_plugins_dir, 'plugins.cfg')
    list_lines = open(ida_plugins_cfg_path, 'r').readlines()
    first_index = \
        list_lines.index(';REDB CALLBACK_FUNCTIONS PARSER: ENTER\n') + 1
    last_index = list_lines.index(';REDB CALLBACK_FUNCTIONS PARSER: EXIT\n')
    CALLBACK_FUNCTIONS = []
    list_lines = list_lines[first_index:last_index]
    for line in list_lines:
        split_line = line.split("\t")
        CALLBACK_FUNCTIONS.append((split_line[0], split_line[2],
                                   split_line[0].lower()))

    return CALLBACK_FUNCTIONS


#==============================================================================
# Decorators
#==============================================================================
def log_calls_decorator(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        print "->" + str(f.__name__)
        try:
            retval = f(*args, **kwargs)
            print str(f.__name__) + "->"
            return retval
        except Exception, e:
            # get traceback info to print out later
            print type(e).__name__
            for frame in traceback.extract_stack():
                print os.path.basename(frame[0]), str(frame[1])
            raise
    return wrapped


#==============================================================================
# HTTP Post
#==============================================================================
# Taken from http://code.activestate.com
def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to
    be uploaded as files. Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()  # @UnusedVariable
    return_data = h.file.read()
    return return_data


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files. Returns (content_type, body) ready for httplib.HTTP
    instance.
    """
    BOUNDARY = mimetools.choose_boundary()
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % \
                  (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def post_non_serialized_data(data, host):
    try:
        serialized_data = json.dumps(data)
        serialized_response =\
            post_multipart(host, "/redb/", [],
                           [("action", "action", serialized_data)])
        response = json.loads(s=serialized_response, object_hook=_decode_dict)
    except:
        response = None

    if response is not None:
        print "REDB: POST successful."
    return response
