"""
This module contains the callback functions and utility functions it uses.
"""

# related third party imports
import idaapi
import idautils
import idc

# local application/library specific imports
import redb_client_utils
import redb_function

# Constants
HANDLED_TAG = "[REDB-handled] "
MIN_INS_PER_HANDLED_FUNCTION = 5

# Should be exactly the same as CALLBACK_FUNCTIONS in install.py.
CALLBACK_FUNCTIONS = [("Information", "Ctrl-Shift-I", "_information"),
                      # interaction with the server
                      ("Submit_Current", "Ctrl-Shift-S", "_submit_one"),
                      ("Request_Current", "Ctrl-Shift-R", "_request_one"),
                      ("Handle_Current", "Ctrl-Shift-H", "_handle_one"),
                      # description browsing
                      ("Next_Public_Description", "Ctrl-Shift-.", "_next"),
                      ("Previous_Public_Description", "Ctrl-Shift-,",
                       "_previous"),
                      ("Restore_User's_Description", "Ctrl-Shift-U",
                       "_restore_user"),
                      ("Merge_Public_Into_User's", "Ctrl-Shift-M", "_merge"),
                      # all-handled callbacks
                      ("Submit_All_Handled", "Ctrl-Shift-Q",
                       "_submit_all_handled"),
                      ("Request_All_Handled", "Ctrl-Shift-W",
                       "_request_all_handled"),
                      # settings
                      ("Settings", "Ctrl-Shift-O", "_settings"),
                      # Debug - add these two tuples to CALLBACK_FUNCTIONS to
                      # enable mass submitting and requesting.
                      # ("Submit_All", "Ctrl-Shift-Z", "_submit_all"),
                      # ("Request_All", "Ctrl-Shift-X", "_request_all"),
                     ]


#==============================================================================
# Client Interface
#==============================================================================
class ClientAction:
    def __init__(self, redb_item, arg):
        """
        Called before each callback function. Collects necessary data about
        the function the user is pointing at.
        """
        self._handled_functions = redb_item._handled_functions
        self._currently_pointing_at_a_function = False
        self._current_function_is_handled = False
        self._string_addresses = redb_item._string_addresses
        self._imported_modules = redb_item._imported_modules

        # Establish if cursor is pointing at a function,
        # and if so, is the function in the handled functions list.
        # updates self._cur_function.
        cur_func = idaapi.get_func(idc.ScreenEA())
        if not cur_func is None:
            self._currently_pointing_at_a_function = True

            first_addr = cur_func.startEA
            self._cur_func_addr = first_addr
            if str(first_addr) in self._handled_functions:
                self._current_function_is_handled = True
                self._cur_func = self._handled_functions[str(first_addr)]

        getattr(self, CALLBACK_FUNCTIONS[arg][2])()

        idaapi.hide_wait_box()

    def _information(self):
        help_string = "\r\nREDB Commands:\r\n"
        help_string += "============\r\n"
        for function in CALLBACK_FUNCTIONS:
            help_string += function[1]
            help_string += "\t"
            help_string += function[0]
            help_string += "\r\n"

        idaapi.info(help_string)

    def _submit_one(self):
        """
        Submits the user's description.
        """
        if self._assert_currently_pointing_at_a_function():
            if self._assert_current_function_is_handled():
                idaapi.show_wait_box("Submitting...")
                try:
                    self._cur_func.submit_description()
                except Exception as e:
                    print "REDB: Unexpected exception thrown while submitting:"
                    print e
                idaapi.hide_wait_box()

    def _request_one(self):
        """
        Request descriptions for a function.
        """
        if self._assert_currently_pointing_at_a_function():
            if self._assert_current_function_is_handled():
                idaapi.show_wait_box("Requesting...")
                try:
                    self._cur_func.request_descriptions()
                except Exception as e:
                    print "REDB: Unexpected exception thrown while requesting:"
                    print e
                idaapi.hide_wait_box()

    def _handle_one(self):
        """
        Add current function to handled.
        """
        if self._assert_currently_pointing_at_a_function():
            try:
                self._handle_function(self._cur_func_addr)
            except Exception as e:
                print "REDB: Unexpected exception thrown:"
                print e

    def _next(self):
        """
        View next public description.
        """
        if self._assert_currently_pointing_at_a_function():
            if self._assert_current_function_is_handled():
                try:
                    self._cur_func.next_description()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _previous(self):
        """
        View previous public description.
        """
        if self._assert_currently_pointing_at_a_function():
            if self._assert_current_function_is_handled():
                try:
                    self._cur_func.previous_description()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _restore_user(self):
        """
        Restore the user's description.
        """
        if self._assert_currently_pointing_at_a_function():
            if self._assert_current_function_is_handled():
                try:
                    self._cur_func.restore_user_description()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _merge(self):
        """
        Merge current public description into the user's description.
        """
        if self._assert_currently_pointing_at_a_function():
            if self._assert_current_function_is_handled():
                try:
                    self._cur_func.merge_public_to_users()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _submit_all_handled(self):
        """
        Submit user description for all handled functions.
        """
        num_of_funcs = str(len(self._handled_functions))
        idaapi.show_wait_box("Submitting " + num_of_funcs + " function...")
        try:
            for function in self._handled_functions:
                self._handled_functions[function].submit_description()
        except Exception as e:
            print "REDB: Unexpected exception thrown while submitting:"
            print e
        idaapi.hide_wait_box()

    def _request_all_handled(self):
        """
        Request descriptions for all handled functions.
        """
        num_of_funcs = str(len(self._handled_functions))
        idaapi.show_wait_box("Requesting Descriptions for " + num_of_funcs + \
                             " function...")
        try:
            for function in self._handled_functions:
                self._handled_functions[function].\
                    request_descriptions()
        except Exception as e:
            print "REDB: Unexpected exception thrown while requesting:"
            print e
        idaapi.hide_wait_box()

    def _settings(self):
        """
        Change configurations.
        """
        parse_config = redb_client_utils.PluginConfig()
        parse_config.change_config()

#-----------------------------------------------------------------------------
# Client Interface Utilities
#-----------------------------------------------------------------------------
    def _prepare_for_callback_func(self):
        """
        Called before each callback function. Collects necessary data about
        the function the user is pointing at.
        """
        self._currently_pointing_at_a_function = False
        self._current_function_is_handled = False

        cur_func = idaapi.get_func(idc.ScreenEA())
        if not cur_func is None:
            self._currently_pointing_at_a_function = True

            first_addr = cur_func.startEA
            self._cur_func_addr = first_addr
            if str(first_addr) in self._handled_functions:
                self._current_function_is_handled = True
                self._cur_func = self._handled_functions[str(first_addr)]

    def _handle_function(self, addr):
        """
        Determines if a function can be handled and if so, handles it.
        """
        first_addr = idaapi.get_func(addr).startEA
        if str(first_addr) in self._handled_functions:
            print "REDB: function is already handled."
        else:
            flags = idc.GetFunctionFlags(first_addr)
            if (flags & (idc.FUNC_THUNK | idc.FUNC_LIB)):
                err_str = "REDB: function has been identified by IDA as a "
                err_str += "thunk or a library function and therefore will "
                err_str += "not be handled."
                print err_str
            else:
                if (len(list(idautils.FuncItems(addr))) < \
                    MIN_INS_PER_HANDLED_FUNCTION):
                    err_str = "REDB: function has too few instructions "
                    err_str += "and therefore will not be handled."
                    print err_str
                else:
                    self._add_to_handled(first_addr)

    def _add_to_handled(self, first_addr):
        """
        Adds a function to handled functions dictionary.
        """
        self._handled_functions[str(first_addr)] = \
            redb_function.REDBFunction(first_addr,
                                       self._string_addresses,
                                       self._imported_modules)
        redb_client_utils.Tag(first_addr).add_tag(user=True)
        print "REDB: Added " + str(first_addr) + " to handled functions."

    def _assert_currently_pointing_at_a_function(self):
        if self._currently_pointing_at_a_function:
            return True
        else:
            print "REDB: Not pointing at a function."
            return False

    def _assert_current_function_is_handled(self):
        if self._current_function_is_handled:
            return True
        else:
            print "REDB: Function is not handled."
            return False

#-----------------------------------------------------------------------------
# DEBUG AND TEST
#-----------------------------------------------------------------------------
    def _submit_all(self):
        """
        Handle all possible functions and then submit their descriptions.
        """
        for function in list(idautils.Functions()):
            self._handle_function(function)
        self._submit_all_handled()

    def _request_all(self):
        """
        Handle all possible functions and then request descriptions for them.
        """
        for function in list(idautils.Functions()):
            self._handle_function(function)
        self._request_all_handled()
    """
    def _request_neighbors(self, first_addr):
        Applying 'request' on immediate neighbors.
        neighbors_list = list(idautils.CodeRefsTo(first_addr, 0))
        func_items = list(idautils.FuncItems(first_addr))
        for item in func_items:
            neighbors_list += list(idautils.CodeRefsFrom(item, 0))
        idaapi.show_wait_box(neighbors_list.amount() +
                             " neighbor functions were found ")
        idaapi.hide_wait_box()
        answer = idc.AskYN(-1, "Do you wish to proceed?")
        idaapi.hide_wait_box()
        if (answer):
            for func_addr in neighbors_list:
                cur_func = idaapi.get_func(func_addr)
    """
