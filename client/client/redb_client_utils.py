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

    @classmethod
    def get_current_from_ini_file(cls, item):
        parser = ConfigParser.SafeConfigParser()
        parser.read(CONFIG_FILE_PATH)
        return parser.get('REDB', item)

    @classmethod
    def change_config(cls):
        try:
            cls.get_current_from_ini_file()
        except:
            host = "<ip>:<port>"
            username = "Username"
            pass_hash = "Password"

        os.remove(CONFIG_FILE_PATH)
        cfgfile = open(CONFIG_FILE_PATH, 'w')
        parser = ConfigParser.SafeConfigParser()
        parser.add_section('REDB')

        host = \
            _getUserConfigInput(host,
                                "REDB: Please enter the server's ip and port:")
        parser.set('REDB', 'host', host)

        username = \
            _getUserConfigInput(username,
                                "REDB: Enter your username:")
        parser.set('REDB', 'username', username)

        pass_hash = \
            _getUserConfigInput(pass_hash,
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
        parse_config.get_current_from_ini_file('host')
        parse_config.get_current_from_ini_file('username')
        parse_config.get_current_from_ini_file('pass_hash')
    except:
        parse_config.change_config()

    return parse_config


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
    response = None
    try:
        serialized_data = json.dumps(data)
        serialized_response =\
            post_multipart(host, "/redb/", [],
                           [("action", "action", serialized_data)])
        response = json.loads(s=serialized_response, object_hook=_decode_dict)
        print "REDB: POST successful."
    except Exception as e:
        print "REDB: Exception thrown while POSTing:"
        print e

    return response
