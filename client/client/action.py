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
class Action(object):
    def __init__(self, redb_item, current_addr):
        self._redb_functions = redb_item._redb_functions
        self._string_addresses = redb_item._string_addresses
        self._imported_modules = redb_item._imported_modules

        self._is_a_function = False
        self._cur_func = None

        # Establish if cursor is pointing at a function,
        # and if so, if the function is in the handled functions list.
        # updates self._cur_function.
        func = idaapi.get_func(current_addr)
        if func is not None:
            self._is_a_function = True
            self._start_addr = func.startEA
            self.func_items = list(idautils.FuncItems(self._start_addr))

            if str(self._start_addr) in self._redb_functions:
                self._cur_func = self._redb_functions[str(self._start_addr)]

    def submit(self):
        result = None
        try:
            if not self._is_a_function:
                return "Not pointing at a function."
            if self._is_lib_thunk():
                return "Lib and thunk functions are not admissible."
            if not self._is_long_enough():
                return "Short functions are not admisible."
            if (not self._is_handled()):
                self._add_function()

            idaapi.show_wait_box("Submitting...")
            result = self._cur_func.submit_description()
        except Exception as e:
            return "Error occurred while submitting: " + str(e)
        else:
            return result
        finally:
            idaapi.hide_wait_box()

    def request(self):
        result = None
        try:
            if not self._is_a_function:
                return "Not pointing at a function."
            if (not self._is_handled()):
                self._add_function()
            idaapi.show_wait_box("Requesting...")
            result = self._cur_func.request_descriptions()
        except Exception as e:
            return "Error occurred while requesting: " + str(e)
        else:
            return result
        finally:
            idaapi.hide_wait_box()

    def restore_user_description(self):
        try:
            if not self._is_a_function:
                return "Not pointing at a function."
            if (not self._is_handled()):
                return "Function not handled (no descriptions saved)."
            self._cur_func.restore_user_description()
        except Exception as e:
            return "Error occurred while restoring: " + str(e)

    def merge(self):
        try:
            if not self._is_a_function:
                return "Not pointing at a function."
            if (not self._is_handled()):
                return "Function not handled (no descriptions saved)."
            self._cur_func.merge_public_to_users()
        except Exception as e:
            return "Error occurred while merging: " + str(e)

    def _is_handled(self):
        return self._cur_func != None

    def _is_lib_thunk(self):
        flags = idc.GetFunctionFlags(self._start_addr)
        return (flags & (idc.FUNC_THUNK | idc.FUNC_LIB))

    def _is_long_enough(self):
        return (len(self.func_items) >= MIN_INS_PER_HANDLED_FUNCTION)

    def _add_function(self):
        """
        Adds a function to handled functions dictionary.
        """
        self._cur_func = function.Function(self._start_addr,
                                           self._string_addresses,
                                           self._imported_modules)
        self._redb_functions[str(self._start_addr)] = self._cur_func


class HotkeyAction(Action):
    def __init__(self, redb_item, hotkey_callbacks, arg, current_addr):
        super(HotkeyAction, self).__init__(redb_item, current_addr)
        self._arg = arg
        self._hotkey_callbacks = hotkey_callbacks
        print self._hotkey_callbacks
        getattr(self, self._hotkey_callbacks[self._arg][2])()

    def information(self):
        print "1"
        help_string = "\r\nREDB Commands:\r\n"
        help_string += "============\r\n"
        for function in self._hotkey_callbacks:
            help_string += function[1]
            help_string += "\t"
            help_string += function[0]
            help_string += "\r\n"

        print help_string

    def submit_current(self):
        print self.submit()

    def request_current(self):
        print self.request()

    def next_public_description(self):
        try:
            if not self._is_a_function:
                print "Not pointing at a function."
            if (not self._is_handled()):
                print "Function not handled (no descriptions saved)."
            self._cur_func.next_description()
        except Exception as e:
            return "An error occurred: " + str(e)

    def previous_public_description(self):
        try:
            if not self._is_a_function:
                print "Not pointing at a function."
            if (not self._is_handled()):
                print "Function not handled (no descriptions saved)."
            self._cur_func.previous_description()
        except Exception as e:
            return "An error occurred: " + str(e)

    def restore_my_description(self):
        print super(HotkeyAction, self).restore_user_description()

    def merge_public_into_users(self):
        print self.merge()

    def settings(self):
        """
        Change configurations.
        """
        for opt in utils.Configuration.OPTIONS.keys():
            value = utils.Configuration.get_opt_from_user(opt)
            utils.Configuration.set_option(opt, value)

#-----------------------------------------------------------------------------
# Client Interface Utilities
#-----------------------------------------------------------------------------

    def _request_neighbors(self):
        """
        Applying 'request' on immediate neighbors.
        """
        # CodeRefsTo current function
        neighbors_list = list(idautils.CodeRefsTo(self._start_addr, 0))

        # CodeRefsFrom current function
        for item in self._cur_func._func_items:
            if idaapi.get_func(item).startEA != self._start_addr:
                neighbors_list += list(idautils.CodeRefsFrom(item, 0))

        # Prompting the user for desired action
        prompt_string = (str(len(neighbors_list)) +
                         " neighbor functions were found.\n " +
                         "Request descriptions for these functions?")
        answer = idc.AskYN(-1, prompt_string)

        # Request neighbor function
        if (answer):
            for func_addr in neighbors_list:
                client = Action(self._redb_item, self._hotkey_callbacks,
                                self._arg, func_addr)
                client._request_one()
