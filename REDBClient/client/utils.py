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
import warnings
import requests

# related third party imports
import idc
import idautils
import idaapi


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


class Post:
    def __init__(self, https=False, verify_cert=False, basic_auth=True,
                 url_suffix='/'):
        """
        if https: try sending over https
        if basic_auth: authenticate using http basic authentication
        if session: use session_token (if one exists), keep session token
        """
        self.data = {}

        if https:
            url_prefix = "https://"
        else:
            url_prefix = "http://"

        self.verify = verify_cert

        host = Configuration.get_option('host')
        self.url = url_prefix + host + url_suffix

        if basic_auth:
            username = Configuration.get_option('username')
            password = Configuration.get_option('password')
            self.auth = (username, password)

        # TODO: handle sessions

    def send(self):
        try:
            # suppressing a cookielib bug warning.
            with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    response = requests.post(self.url, self.data,
                                             auth=self.auth,
                                             verify=self.verify)
        except AttributeError as e:
            if e.message == "'NoneType' object has no attribute 'Lock'":
                print ("Exception caught: " + e.message + '\n' +
                       "Known issue in connectionpool.py\n" +
                       "See https://github.com/shazow/urllib3/issues/229\n" +
                       "Duct tape fix:\n" +
                       "in connectionpool.py, for python 2.7,\n" +
                       "after 'from Queue import LifoQueue, Empty, Full',\n" +
                       "add 'import Queue'")
                return "Error sending. See Console."
        except requests.exceptions.ConnectionError as e:
            msg = e.message
            if isinstance(msg, Exception):
                return msg.message
            else:
                return str(msg)

        # Handling response
        if response.status_code == 200:  # Success
            try:
                res_data = response.json(object_hook=_decode_dict)
            except:
                return "Error: response data is in invalid format."
            if isinstance(res_data, unicode):
                res_data = str(res_data)
            return res_data
        else:  # HTTP Failure
            return "HTTP Error: " + str(response.status_code)

    def add_data(self, key, deserialized_value):
        self.data[key] = json.dumps(deserialized_value,
                                    encoding='ISO-8859-1')


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
               "password": ""}

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
            if opt != "password":
                try:
                    defval = cls.get_option(opt)
                except:
                    defval = cls.OPTIONS[opt]
            else:
                defval = cls.OPTIONS[opt]

            try:
                value = idc.AskStr(defval, cls.OPTIONS[opt])
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


def get_ret_offset_in_stack(first_addr):
    try:
        stack = idc.GetFrame(first_addr)
        return idc.GetMemberOffset(stack, ' r')
    except:
        return None


def get_argument_offsets_in_stack_list(first_addr):
    offset_list = []
    try:
        stack = idc.GetFrame(first_addr)
        stack_size = idc.GetStrucSize(stack)
        name_set = set(idc.GetMemberName(stack, i) for i in xrange(stack_size))
        if ' r' not in name_set:
            return offset_list
        ret_offset = idc.GetMemberOffset(stack, ' r')
        offset_list = [idc.GetMemberOffset(stack, name) for name in name_set]
        offset_list = filter(lambda offset: offset > ret_offset, offset_list)
    except:
        pass
    return offset_list


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


def _generate_hotkey_table():
    ida_plugins_dir = idaapi.idadir("plugins")
    ida_plugins_cfg_path = os.path.join(ida_plugins_dir, 'plugins.cfg')
    list_lines = open(ida_plugins_cfg_path, 'r').readlines()
    first_index = list_lines.index(';REDB: ENTER\n') + 1
    try:
        last_index = list_lines.index(';REDB: EXIT\n')
    except:
        last_index = list_lines.index(';REDB: EXIT')
    hotkeys = []
    list_lines = list_lines[first_index:last_index]
    for line in list_lines:
        split_line = line.split("\t")
        hotkeys.append((split_line[0].replace('_', ' '), split_line[2]))

    return hotkeys


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
        return "No response from server."

    response = None
    try:
        response = json.loads(s=serialized_response, object_hook=_decode_dict)
    except ValueError:
        return "Server: " + serialized_response

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
    GLADE_DIR_PATH = os.path.dirname(__file__)
    GLADE_FILE_PATH = os.path.join(GLADE_DIR_PATH, 'redb_gui.glade')

    COLUMNS = ["Index", "Name", "Number of comments", "Grade", "User",
               "Last Modified", "Exe Names"]

    HISTORY_COLUMNS = ["Index", "Name", "Number of comments",
                       "Before Embedding"]

    def __init__(self, callbacks, gtk_module):
        self.gtk = gtk_module
        self.callbacks = callbacks
        self.exists = False

    def add_descriptions(self, description_list):
        """
        Each description is a list. See GuiMenu.COLUMNS.
        """
        for description in description_list:
            self.descriptions.append(description)

    def add_history(self, history_list):
        """
        Each description is a list. See GuiMenu.HISTORY_COLUMNS.
        """
        for description in history_list:
            self.history_buffer.append(description)

    def remove_all_rows(self):
        self.descriptions.clear()

    def get_selected_item_index(self, table):
        selection = table.get_selection()
        model, it = selection.get_selected()
        return model.get(it, 0)[0]

    def get_selected_description_index(self):
        return self.get_selected_item_index(self.description_table)

    def get_selected_history_index(self):
        return self.get_selected_item_index(self.history_table)

    def set_status_bar(self, text):
        self.status_bar.push(0, text)

    def set_details(self, text):
        self.description_details.get_buffer().set_text(text)

    def load_xml(self):
        # Read structure from glade file
        self.xml = self.gtk.Builder()
        self.xml.add_from_file(GuiMenu.GLADE_FILE_PATH)

        # Connect callback functions
        self.xml.connect_signals(self.callbacks)

        # For future reference
        self._get_widgets()

        # Instantiate description table
        self._init_description_table()

        # Instantiate history table
        self._init_history_table()

    def show(self):
        if not self.exists:
            self.exists = True
            self.gtk.main()
        else:
            self.main_window.present()

    def hide(self):
        if self.exists:
            self.exists = False
            self.main_window.destroy()
            self.gtk.main_quit()

    def _get_widgets(self):
        self.main_window = self.xml.get_object("MainWindow")

        # Toolbars
        self.top_toolbar = self.xml.get_object("TopToolbar")
        self.bottom_toolbar = self.xml.get_object("BottomToolbar")

        # descriptions
        self.desc_scrolled_window = \
            self.xml.get_object("DescriptionScrolledWindow")
        self.description_table = self.xml.get_object("DescriptionTable")

        # description details
        self.details_scrolled_window = \
            self.xml.get_object("DetailsScrolledWindow")
        self.description_details = \
            self.xml.get_object("DescriptionDetails")

        # saved history
        self.history_scrolled_window = \
             self.xml.get_object("HistoryScrolledWindow")
        self.history_table = self.xml.get_object("HistoryTable")

        # status bar
        self.status_bar = self.xml.get_object("StatusBar")

        # buttons
        self.undo_button = self.xml.get_object("tbUndo")
        self.redo_button = self.xml.get_object("tbRedo")

    def _init_description_table(self):
        self.descriptions = \
        self.gtk.ListStore(int, str, int, float, str, str, str)
        self.description_table.set_model(self.descriptions)
        for column_title in GuiMenu.COLUMNS:
            self._add_column(column_title, GuiMenu.COLUMNS.index(column_title))

    def _init_history_table(self):
        self.history_buffer = \
            self.gtk.ListStore(int, str, int, str)
        self.history_table.set_model(self.history_buffer)
        for column_title in GuiMenu.HISTORY_COLUMNS:
            self._add_column_history(column_title,
                                GuiMenu.HISTORY_COLUMNS.index(column_title))

    def _add_column(self, title, columnId):
        column = self.gtk.TreeViewColumn(title,
                                         self.gtk.CellRendererText(),
                                         text=columnId)
        column.set_sizing(self.gtk.TREE_VIEW_COLUMN_AUTOSIZE)
        column.set_resizable(True)
        column.set_sort_column_id(columnId)
        self.description_table.append_column(column)

    def _add_column_history(self, title, columnId):
        column = self.gtk.TreeViewColumn(title,
                                         self.gtk.CellRendererText(),
                                         text=columnId)

        column.set_sizing(self.gtk.TREE_VIEW_COLUMN_AUTOSIZE)
        column.set_resizable(True)
        column.set_sort_column_id(columnId)
        self.history_table.append_column(column)
