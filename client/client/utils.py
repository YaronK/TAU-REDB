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

GUI_ENABLED = True
try:
    import pygtk
    print "imported pygtk"
    pygtk.require("2.0")
    print "yaron"
    import gtk.glade
    # from gtk import glade
    print "imported gtk"
    GLADE_DIR_PATH = os.path.dirname(__file__)
    GLADE_FILE_PATH = os.path.join(GLADE_DIR_PATH, 'redb_gui.glade')
except:
    GUI_FLAG = False


#==============================================================================
# Decorators
#==============================================================================
def log(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        print "enter: " + str(f.__name__)
        try:
            retval = f(*args, **kwargs)
            print "exit: " + str(f.__name__)
            return retval
        except Exception, e:
            # get traceback info to print out later
            print type(e).__name__
            for frame in traceback.extract_stack():
                print os.path.basename(frame[0]), str(frame[1])
            raise
    return wrapped


#==============================================================================
# Configuration
#==============================================================================
class Configuration:
    """
    Configuration management.
    """
    PLUGIN_DIR_PATH = os.path.dirname(__file__)
    CONFIG_FILE_PATH = os.path.join(PLUGIN_DIR_PATH, 'IdaProject.INI')
    SECTION = "REDB"
    OPTIONS = {"host": "Host (ip:port)",
               "username": "Username",
               "password": "Password"}

    @classmethod
    def get_option(cls, opt):
        config = ConfigParser.SafeConfigParser()
        config.read(cls.CONFIG_FILE_PATH)
        return config.get(cls.SECTION, opt)

    @classmethod
    def set_option(cls, opt, value):
        config = ConfigParser.SafeConfigParser()
        config.read(cls.CONFIG_FILE_PATH)
        config.set(cls.SECTION, opt, value)
        with open(cls.CONFIG_FILE_PATH, 'wb') as configfile:
            config.write(configfile)

    @classmethod
    def assert_config_file_validity(cls):
        if not os.path.exists(cls.CONFIG_FILE_PATH):
            print "REDB: Configuration file does not exist."
            open(cls.CONFIG_FILE_PATH, 'wb').close()

        # Configuration file exists
        config = ConfigParser.SafeConfigParser()
        config.read(cls.CONFIG_FILE_PATH)
        if not config.has_section(cls.SECTION):
            config.add_section(cls.SECTION)
        # Section exists
        for opt in cls.OPTIONS.keys():
            if not config.has_option(cls.SECTION, opt):
                config.set(cls.SECTION, opt, cls.get_opt_from_user(opt))
        # Options exist
        with open(cls.CONFIG_FILE_PATH, 'wb') as configfile:
            config.write(configfile)

    @classmethod
    def get_opt_from_user(cls, opt):
        value = None
        while value is None:
            try:
                value = idc.AskStr(cls.OPTIONS[opt], cls.OPTIONS[opt])
            except:
                pass
        return value


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
@log
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
    first_index = list_lines.index(';REDB: ENTER\n') + 1
    try:
        last_index = list_lines.index(';REDB: EXIT\n')
    except:
        last_index = list_lines.index(';REDB: EXIT')
    CALLBACK_FUNCTIONS = []
    list_lines = list_lines[first_index:last_index]
    for line in list_lines:
        split_line = line.split("\t")
        CALLBACK_FUNCTIONS.append((split_line[0], split_line[2],
                                   split_line[0].lower()))

    return CALLBACK_FUNCTIONS


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
    serialized_data = json.dumps(data)
    serialized_response = \
        post_multipart(host, "/redb/", [],
                       [("action", "action", serialized_data)])

    if serialized_response == None:
        print "REDB: No response from server."
        return None

    response = None
    try:
        response = json.loads(s=serialized_response, object_hook=_decode_dict)
    except ValueError:
        print "REDB, Response: " + serialized_response

    return response


class ServerQuery:
    def __init__(self, query_type, username, password, data_dict):
        self.type = query_type
        self.username = username
        self.password = password
        self.data = data_dict

    def to_dict(self):
        return {"type": self.type,
                "username": self.username,
                "password": self.password,
                "data": self.data}


#==============================================================================
# GUI
#==============================================================================
class GuiMenu:
    def __init__(self):
        print "Menu"
        self.wTree = gtk.glade.XML(GLADE_FILE_PATH, "mainWindow")
        print "0"
        callbacks = {"on_mainWindow_destroy": gtk.main_quit,
                     "on_Submit": self.Submit,
                     "on_Request": self.Request,
                     "on_Restore": self.Restore,
                     "on_Settings": self.Settings,
                     "on_Show": self.Show,
                     "on_Merge": self.Merge,
                     "on_Details": self.Details}

        self.wTree.signal_autoconnect(callbacks)

        # Column numbers
        self.cDescIndex = 0
        self.cFuncName = 1
        self.cFuncNumCmts = 2
        self.cFuncGrade = 3
        self.cDescUser = 4
        self.cDescDate = 5

        # Column titles
        self.sDescIndex = "Index"
        self.sFuncName = "Name"
        self.sFuncNumCmts = "Number of comments"
        self.sFuncGrade = "Grade"
        self.sDescUser = "User"
        self.sDescDate = "Last Modified"

        # Main Widget
        self.DescriptionView = self.wTree.get_widget("DescriptionView")
        self.DescriptionList = gtk.ListStore(int, str, int, float, str, str)
        self.DescriptionView.set_model(self.DescriptionList)

        # Adding Columns
        self.AddDescriptionListColumn(self.sDescIndex, self.cDescIndex)
        self.AddDescriptionListColumn(self.sFuncName, self.cFuncName)
        self.AddDescriptionListColumn(self.sFuncNumCmts, self.cFuncNumCmts)
        self.AddDescriptionListColumn(self.sFuncGrade, self.cFuncGrade)
        self.AddDescriptionListColumn(self.sDescUser, self.cDescUser)
        self.AddDescriptionListColumn(self.sDescDate, self.cDescDate)
        print "1"
        gtk.main()
        print "/Menu"

    def AddDescriptionListColumn(self, title, columnId):
        """This function adds a column to the list view.
        First it create the gtk.TreeViewColumn and then set
        some needed properties"""

        column = gtk.TreeViewColumn(title, gtk.CellRendererText(),
                                    text=columnId)

        column.set_resizable(True)
        column.set_sort_column_id(columnId)
        self.DescriptionView.append_column(column)

    def Submit(self, widget):
        print "Submit description"

    def Request(self, widget):
        # self.DescriptionList.append([1, "func", 5, 0.98, "yasmin", "12345"])
        print "Request description"

    def Restore(self, widget):
        print "Restore description"

    def Settings(self, widget):
        print "Settings"

    def Show(self, widget):
        description_index = self.DescriptionView.get_selection().get_selected_rows()[0][0][0]
        print description_index
        print "Show description"

    def Merge(self, widget):
        description_index = self.DescriptionView.get_selection().get_selected_rows()[0][0][0]
        print "Merge description"

    def Details(self, widget):
        description_index = self.DescriptionView.get_selection().get_selected_rows()[0][0][0]
        # details = DescriptionDetails(self.gladefile)
        # details.run()
        print "Details description"


class DescriptionDetails:
    def __init__(self, details):
        print "Details"
        wTree = gtk.glade.XML(GLADE_FILE_PATH, "DescriptionDetails")
        descriptionDetalils = wTree.get_widget("DescriptionDetails")
        details = wTree.get_widget("details")
        details_buffer = details.get_buffer()
        details_buffer.set_text(details)
        descriptionDetalils.run()
        descriptionDetalils.destroy()
        print "/Details"
