"""
Utilities for all the other modules.
"""

# standard library imports
import os
import shutil
import traceback
import functools

# standard library imports
import ConfigParser
import string

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
# Comments and function name and Tag management
#==============================================================================
class Extract:
    """
    Extraction of current comments and getting the function name.
    """
    def __init__(self, first_addr):
        self._first_addr = first_addr
        self._func_items = list(idautils.FuncItems(self._first_addr))

    def extract_all(self):
        dic = {}

        dic["func_name"] = self._extract_func_name()
        dic["comments"] = self._extract_comments()
        dic["func_comment"] = self._extract_func_comment()
        dic["stack_members"] = self._extract_stack_members()

        return dic

    def _extract_func_name(self):
        return idc.GetFunctionName(self._first_addr)

    def _extract_comments(self):
        comments = []

        ea_reg_com_filter = lambda ea: (idc.GetCommentEx(ea, 0) is not None)
        ea_reg_com_set = filter(ea_reg_com_filter, self._func_items)
        comments += [(ea - self._first_addr, 0, idc.GetCommentEx(ea, 0))
                     for ea in ea_reg_com_set]

        ea_rep_com_filter = lambda ea: (idc.GetCommentEx(ea, 1) is not None)
        ea_rep_com_set = filter(ea_rep_com_filter, self._func_items)
        comments += [(ea - self._first_addr, 1, idc.GetCommentEx(ea, 1))
                     for ea in ea_rep_com_set]

        return comments

    def _extract_func_comment(self):
        function_comments = []

        reg_cmt = idc.GetFunctionCmt(self._first_addr, 0)
        if reg_cmt is not None:
            function_comments.append((0, reg_cmt))

        rep_cmt = idc.GetFunctionCmt(self._first_addr, 1)
        if rep_cmt is not None:
            function_comments.append((1, rep_cmt))

        return function_comments

    def _extract_stack_members(self):
        """
        Generates and returns a list of stack members (variables and
        arguments).
        member := (offset in stack, name, size, flag, regular comment,
        repeatable comment)
        Excludes ' r' and ' s'.
        """
        stack = idc.GetFrame(self._first_addr)
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


class Embed:
    def __init__(self, first_addr, description_dict):
        self._first_addr = first_addr

        self._func_name = description_dict["func_name"]
        self._comments = description_dict["comments"]
        self._func_comment = description_dict["func_comment"]
        self._stack_members = description_dict["stack_members"]

    def embed_all(self, merge):
        if not merge:
            remove_all_comments(self._first_addr)

        self._embed_func_name()
        self._embed_stack_members()

        self._embed_comments(merge)
        self._embed_func_comment(merge)

    def _embed_func_name(self):
        idaapi.set_name(self._first_addr, self._func_name, idaapi.SN_NOWARN)

    def _embed_stack_members(self):
        """
        Setting member attributes should be done in a more delicate manner:
        Only set name and comment if member exists (same size, flags).
        We currently do not create new members.
        assumes member structure defined at GetStackMembers().
        """
        stack = idc.GetFrame(self._first_addr)
        member_filter_lambda =\
            lambda member: ((idc.GetMemberFlag(stack, member[0]) == member[3])
                            and
                            (idc.GetMemberSize(stack, member[0]) == member[2]))

        filtered_member_set = filter(member_filter_lambda, self._stack_members)

        member_set_data_lambda =\
            lambda member: (idc.SetMemberName(stack, member[0], member[1]),
                            idc.SetMemberComment(stack, member[0], 0,
                                                 member[4]),
                            idc.SetMemberComment(stack, member[0], 1,
                                                 member[5]))

        map(member_set_data_lambda, filtered_member_set)

    def _embed_comments(self, merge):
        for (offset, repeatable, text) in self._comments:
            real_ea = self._first_addr + offset
            if merge:
                    text = (idc.GetCommentEx(real_ea, repeatable) +
                            "; " + text)
            if repeatable:
                idc.MakeRptCmt(real_ea, text)
            else:
                idc.MakeComm(real_ea, text)

    def _embed_func_comment(self, merge):
        for (repeatable, text) in self._func_comment:
            if merge:
                    text = (idc.GetFunctionCmt(self._first_addr, repeatable) +
                            "; " + text)
            idc.SetFunctionCmt(self._first_addr, text, repeatable)


def remove_all_comments(first_addr):
    """
    Removing all current comments.
    """
    for func_item in list(idautils.FuncItems(first_addr)):
        idc.MakeComm(func_item, "")
        idc.MakeRptCmt(func_item, "")
    idc.SetFunctionCmt(first_addr, "", 0)
    idc.SetFunctionCmt(first_addr, "", 1)


class Tag:
    """
    Adding a speciel tag in the "function comment".
    """
    def __init__(self, first_addr):
        self._first_addr = first_addr

    def add_tag(self, user=True, index=None, outof=None, mg=None):
        self.remove_tag()

        tag = "[REDB: handled"
        if user:
            tag += ", user's description"
        else:
            tag += (", public description" +
                    " (" + str(index) + "/" + str(outof) + ")" +
                    ", Matching Grade: " + str(mg))
        tag += "]"

        current_comment = Extract(self._first_addr)._extract_func_cmnt(0)
        final_comment = tag
        if current_comment is not None:
            final_comment += current_comment
        Embed(self._first_addr)._embed_func_cmnt(final_comment, 0)
        idaapi.refresh_idaview_anyway()

    # (best effort)
    def remove_tag(self):
        current_comment = Extract(self._first_addr)._extract_func_cmnt(0)
        if string.find(current_comment, "[REDB: handled") == 0:
            last_index = string.find(current_comment, "]")
            final_comment = current_comment[last_index + 1:]
            Embed(self._first_addr)._embed_func_cmnt(final_comment, 0)
            idaapi.refresh_idaview_anyway()


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
