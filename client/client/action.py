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
import hashlib
import copy


#==============================================================================
# Client Interface
#==============================================================================
class Actions(object):
    def __init__(self):
        idaapi.show_wait_box("REDB Plugin is loading, please wait...")

        self.functions = {}

        utils._backup_idb_file()
        utils.Configuration.assert_config_file_validity()
        self._collect_string_addresses()
        self._collect_imported_modules()

        print "*** REDB Plugin loaded. ***"
        idaapi.hide_wait_box()

    def _submit_cur_func(self):
        if not self._set_cur_func():
            return "Not pointing at a function."
        return self.cur_func.submit_description()

    def _request_cur_func(self):
        if not self._set_cur_func():
            return "Not pointing at a function."
        return self.cur_func.request_descriptions()

    def _set_cur_func(self):
        """
        Sets self.cur_func to be the function instance of the function the
        user is currently pointing at. Sets it to None if user is not pointing
        at a function. If current function hasn't been processed using the
        plugin, it is added the function list.
        Returns True iff currently pointing at a function.
        """
        func = idaapi.get_func(idc.ScreenEA())
        if isinstance(func, idaapi.func_t):
            if str(func.startEA) not in self.functions:
                self._add_function(func.startEA)
            self.cur_func = self.functions[str(func.startEA)]
            return True
        else:
            self.cur_func = None
            return False

    def _collect_string_addresses(self):
        self.string_addresses = [string.ea for string in idautils.Strings()]

    def _collect_imported_modules(self):
        self.imported_modules = \
            utils.ImportsAndFunctions().collect_imports_data()

    def _add_function(self, startEA):
        func = function.Function(startEA, self.string_addresses,
                                 self.imported_modules)
        self.functions[str(startEA)] = func

    def _show_public_description(self, index):
        return self.cur_func.show_description_by_index(index)

    def _show_history_description(self, index):
        return self.cur_func.show_history_item_by_index(index)


class HotkeyActions(Actions):
    def __init__(self):
        Actions.__init__(self)
        self._hotkeys = utils._generate_hotkey_table()

    def action(self, arg):
        action_name = self._hotkeys[arg][0]

        if action_name == "Information":
            self._hotkey_information(self._hotkeys)
        elif action_name == "Submit current":
            self._hotkey_submit_current()
        elif action_name == "Request current":
            self._hotkey_request_current()
        elif action_name == "Next public description":
            self._hotkey_next_public_desc()
        elif action_name == "Previous public description":
            self._hotkey_prev_public_desc()
        elif action_name == "Settings":
            self._hotkey_settings()

    def _hotkey_information(self, hotkeys):
        help_string = "\r\nREDB HotkeyActions:\r\n"
        help_string += "===========\r\n"
        for function in hotkeys:
            help_string += function[1]
            help_string += "\t"
            help_string += function[0]
            help_string += "\r\n"
        print help_string

    def _hotkey_submit_current(self):
        print self._submit_cur_func()

    def _hotkey_request_current(self):
        print self._request_cur_func()

    def _hotkey_next_public_desc(self):
        if not self._set_cur_func():
            print "Not pointing at a function."
        #print self.cur_func.show_next_description()

    def _hotkey_prev_public_desc(self):
        if not self._set_cur_func():
            print "Not pointing at a function."
        #print self.cur_func.show_prev_description()

    def _hotkey_settings(self):
        for opt in utils.Configuration.OPTIONS.keys():
            value = utils.Configuration.get_opt_from_user(opt)
            if opt == "password":
                m = hashlib.md5()
                m.update(value)
                value = m.hexdigest()
            utils.Configuration.set_option(opt, value)

    def term(self):
        pass


class GuiActions(HotkeyActions):
    def __init__(self, gtk):
        HotkeyActions.__init__(self)
        callbacks = {"on_mainWindow_destroy": self._on_mainWindow_destroy,
                     "on_Submit": self._on_Submit,
                     "on_Request": self._on_Request,
                     "on_Settings": self._on_Settings,
                     "on_Embed": self._on_Embed,
                     "on_Embed_history": self._on_Embed_history,
                     "on_DescriptionTable_cursor_changed":
                        self._on_DescriptionTable_cursor_changed,
                     "on_HistoryTable_cursor_changed":
                        self._on_HistoryTable_cursor_changed}
        self.gui_menu = utils.GuiMenu(callbacks, gtk)

    def action(self, arg):
        action_name = self._hotkeys[arg][0]
        if action_name == "GUI":
            self.load_gui()
        else:
            HotkeyActions.action(self, arg)

    def load_gui(self):
        self.gui_menu.load_xml()
        if self._set_cur_func():
            desc_rows = self._generate_description_rows()
            self.gui_menu.add_descriptions(desc_rows)
            history_rows = self._generate_history_rows()
            self.gui_menu.add_history(history_rows)

        self.gui_menu.show()

    def _on_mainWindow_destroy(self, widget):
        self._destroy_main_window()

    def _on_Submit(self, widget):
        result = self._submit_cur_func()
        self.gui_menu.set_status_bar(result)

    def _on_Request(self, widget):
        result = self._request_cur_func()
        self.gui_menu.set_status_bar(result)

        self.gui_menu.remove_all_rows()
        self.gui_menu.set_details("")
        desc_rows = self._generate_description_rows()
        self.gui_menu.add_descriptions(desc_rows)

    def _on_Settings(self, widget):
        HotkeyActions._hotkey_settings(self)
        self.gui_menu.show()
        self.gui_menu.set_status_bar("Settings saved.")

    def _on_Embed(self, widget, arg2=None, arg3=None):
        # TODO: check we haven't changed function
        index = self.gui_menu.get_selected_description_index()
        result = self._show_public_description(index)
        self.gui_menu.history_buffer.clear()
        history_rows = self._generate_history_rows()
        self.gui_menu.add_history(history_rows)
        self.gui_menu.set_status_bar(result)

    def _on_Embed_history(self, widget, arg2=None, arg3=None):
        index = self.gui_menu.get_selected_history_index()
        result = self._show_history_description(index)
        self.gui_menu.history_buffer.clear()
        history_rows = self._generate_history_rows()
        self.gui_menu.add_history(history_rows)
        self.gui_menu.set_status_bar(result)

    def _on_item_cursor_changed(self, item_container, table):
        index = self.gui_menu.get_selected_item_index(table)
        description = self.cur_func.get_item_by_index(index, item_container)
        self.gui_menu.set_details(self._data_to_details(description.data))

    def _on_DescriptionTable_cursor_changed(self, widget):
        index = self.gui_menu.get_selected_description_index()
        description = self.cur_func._public_descriptions[index]
        self.gui_menu.set_details(self._data_to_details(description.data))

    def _on_HistoryTable_cursor_changed(self, widget):
        index = self.gui_menu.get_selected_history_index()
        description = self.cur_func._history_buffer[index]
        self.gui_menu.set_details(self._data_to_details(description.data))

    def _destroy_main_window(self):
        self.gui_menu.hide()

    def _generate_description_rows(self):
        descs = self.cur_func._public_descriptions
        return [[descs.index(desc)] +
                desc.get_public_desc_row() for desc in descs]

    def _generate_history_rows(self):
        history_buffer = self.cur_func._history_buffer
        return [[i] + history_buffer[i].get_history_row() for i in
                range(len(history_buffer))]

    def _data_to_details(self, data):
        details = ""

        def list_to_details(lst, line_format):
            details = ""
            for item in lst:
                details += "\t"
                for format_item in line_format:
                    details += format_item + ": "
                    details += str(item[line_format[format_item]]) + "\t\t "
                details += "\n"
            return details

        details += "Function comments:\n"
        func_comments_line_format = {"Repeatable": 0,
                                     "Text": 1}
        details += list_to_details(data["func_comments"],
                                   func_comments_line_format)

        details += "Comments:\n"
        comments_line_format = {"Repeatable": 1,
                                "Relative address": 0,
                                "Text": 2}
        details += list_to_details(data["comments"], comments_line_format)

        details += "Stack members:\n"
        stack_members_line_format = {"Address": 0,
                                     "Name": 1}
        details += list_to_details(data["stack_members"],
                                   stack_members_line_format)
        return details

    def term(self):
        HotkeyActions.term(self)
        self._destroy_main_window()
