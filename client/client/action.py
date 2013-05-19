"""
This module contains the callback functions and utility functions it uses.
"""

# related third party imports
import idaapi
import idautils
import idc

# local application/library specific imports
import function
import utils

# Constants
MIN_INS_PER_HANDLED_FUNCTION = 5


#==============================================================================
# Client Interface
#==============================================================================
class Actions():
    REDB_FUNCTIONS = {}
    STRING_ADDRESSES = []
    IMOPRTED_MODULES = []

    @classmethod
    def initialize(cls):
        """
        Preparations which take place in the loading process.
        """
        idaapi.show_wait_box("REDB Plugin is loading, please wait...")

        utils._backup_idb_file()
        utils.Configuration.assert_config_file_validity()
        cls._collect_string_addresses()
        cls._collect_imported_modules()

        print "*** REDB Plugin loaded. ***"
        idaapi.hide_wait_box()

    @classmethod
    def submit_current(cls):
        func = cls._get_current_function()
        if not isinstance(func, function.Function):
            return func

        first_addr = func._first_addr
        func_items = func._func_items
        num_of_insns = len(func_items)

        if cls._is_lib_thunk(first_addr):
            return "Lib and thunk functions are not admissible."
        if not cls._is_long_enough(num_of_insns):
            return "Short functions are not admisible."

        idaapi.show_wait_box("Submitting...")
        try:
            result = func.submit_description()
        except Exception as e:
            return "Error occurred while submitting: " + str(e)
        else:
            return result
        finally:
            idaapi.hide_wait_box()

    @classmethod
    def request_current(cls):
        func = cls._get_current_function()
        if not isinstance(func, function.Function):
            return func

        idaapi.show_wait_box("Requesting...")
        try:
            result = func.request_descriptions()
        except Exception as e:
            return "Error occurred while requesting: " + str(e)
        else:
            return result
        finally:
            idaapi.hide_wait_box()

    @classmethod
    def restore_user_description(cls):
        func = cls._get_current_function()
        if not isinstance(func, function.Function):
            return func
        return func.restore_user_description()

    @classmethod
    def merge(cls):
        func = cls._get_current_function()
        if not isinstance(func, function.Function):
            return func
        return func.merge_public_to_users()

    @classmethod
    def _get_current_function(cls):
        func = idaapi.get_func(idc.ScreenEA())
        if func is None:
            return "Not pointing at a function."
        if str(func.startEA) not in cls.REDB_FUNCTIONS:
            cls._add_function(func.startEA)
        return cls.REDB_FUNCTIONS[str(func.startEA)]

    @classmethod
    def _collect_string_addresses(cls):
        cls.STRING_ADDRESSES = [string.ea for string in idautils.Strings()]

    @classmethod
    def _collect_imported_modules(cls):
        cls.IMOPRTED_MODULES = \
            utils.ImportsAndFunctions().collect_imports_data()

    @classmethod
    def _is_lib_thunk(cls, startEA):
        flags = idc.GetFunctionFlags(startEA)
        return (flags & (idc.FUNC_THUNK | idc.FUNC_LIB))

    @classmethod
    def _is_long_enough(cls, num_of_insns):
        return (num_of_insns >= MIN_INS_PER_HANDLED_FUNCTION)

    @classmethod
    def _add_function(cls, startEA):
        func = function.Function(startEA, cls.STRING_ADDRESSES,
                                 cls.IMOPRTED_MODULES)
        cls.REDB_FUNCTIONS[str(startEA)] = func

    @classmethod
    def term(cls):
        idaapi.hide_wait_box()
        for function in cls.REDB_FUNCTIONS.values():
            function.restore_user_description()


class Hotkeys():
    @classmethod
    def hotkey_submit_current(cls):
        print Actions.submit_current()

    @classmethod
    def hotkey_request_current(cls):
        print Actions.request_current()

    @classmethod
    def hotkey_next_public_desc(cls):
        func = Actions._get_current_function()
        if not isinstance(func, function.Function):
            return func
        print func.show_next_description()

    @classmethod
    def hotkey_prev_public_desc(cls):
        func = Actions._get_current_function()
        if not isinstance(func, function.Function):
            return func
        print func.show_prev_description()

    @classmethod
    def hotkey_restore_user_description(cls):
        return Actions.restore_user_description()

    @classmethod
    def hotkey_merge(cls):
        return Actions.merge()

    @classmethod
    def hotkey_settings(cls):
        for opt in utils.Configuration.OPTIONS.keys():
            value = utils.Configuration.get_opt_from_user(opt)
            utils.Configuration.set_option(opt, value)


class GuiActions:
    GTK = None
    GUI_MENU = None
    CALLBACKS = None

    @classmethod
    def initialize(cls, gtk):
        cls.GTK = gtk
        cls.CALLBACKS = {"on_mainWindow_destroy": cls.on_mainWindow_destroy,
                         "on_Submit": cls.on_Submit,
                         "on_Request": cls.on_Request,
                         "on_Restore": cls.on_Restore,
                         "on_Settings": cls.on_Settings,
                         "on_Show": cls.on_Show,
                         "on_Merge": cls.on_Merge,
                         "on_DescriptionTable_cursor_changed":
                            cls.on_DescriptionTable_cursor_changed}

    @classmethod
    def show_mainWindow(cls):
        if cls.GUI_MENU == None:
            cls.GUI_MENU = utils.GuiMenu(cls.CALLBACKS, cls.GTK)

    @classmethod
    def on_mainWindow_destroy(cls, widget):
        pass

    @classmethod
    def on_Submit(cls, widget):
        print Actions.submit_current()

    @classmethod
    def on_Request(cls, widget):
        print Actions.request_current()

    @classmethod
    def on_Restore(cls, widget):
        return Actions.restore_user_description()

    @classmethod
    def on_Settings(cls, widget):
        for opt in utils.Configuration.OPTIONS.keys():
            value = utils.Configuration.get_opt_from_user(opt)
            utils.Configuration.set_option(opt, value)

    @classmethod
    def on_Show(cls, widget):
        func = Actions._get_current_function()
        if not isinstance(func, function.Function):
            return func
        print func.show_next_description()

    @classmethod
    def on_Merge(cls, widget):
        return Actions.merge()

    @classmethod
    def on_DescriptionTable_cursor_changed(cls, widget):
        pass
