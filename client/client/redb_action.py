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
                      ("Request_Current", "Ctrl-Shift-R", "_request"),
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
    def __init__(self, redb_item, arg, current_addr, plugin_configuration):
        """
        Called before each callback function. Collects necessary data about
        the function the user is pointing at.
        """
        self._arg = arg
        self._redb_item = redb_item
        self._redb_functions = redb_item._redb_functions
        self._currently_pointing_at_a_function = False
        self._string_addresses = redb_item._string_addresses
        self._imported_modules = redb_item._imported_modules
        self._cur_func = None
        self._plugin_configuration = plugin_configuration

        # Establish if cursor is pointing at a function,
        # and if so, if the function is in the handled functions list.
        # updates self._cur_function.
        func = idaapi.get_func(current_addr)
        if not func is None:
            self._currently_pointing_at_a_function = True
            self._start_addr = func.startEA

            if str(self._start_addr) in self._redb_functions:
                self._cur_func = self._redb_functions[str(self._start_addr)]

    def run(self):
        getattr(self, CALLBACK_FUNCTIONS[self._arg][2])()

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
        if self._is_pointing_at_a_function():
            if (not self._is_handled()):
                if (self._is_admissable()):
                    self._add_function()
                else:
                    return

            idaapi.show_wait_box("Submitting...")
            try:
                self._cur_func.submit_description()
            except Exception as e:
                print "REDB: Unexpected exception thrown while submitting:"
                print e
            idaapi.hide_wait_box()

    def _request(self):
        """
        Request descriptions for a function.
        """
        self._request_one()
        self._request_neighbors()

    def _next(self):
        """
        View next public description.
        """
        if self._is_pointing_at_a_function():
            if self._is_handled():
                try:
                    self._cur_func.next_description()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _previous(self):
        """
        View previous public description.
        """
        if self._is_pointing_at_a_function():
            if self._is_handled():
                try:
                    self._cur_func.previous_description()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _restore_user(self):
        """
        Restore the user's description.
        """
        if self._is_pointing_at_a_function():
            if self._is_handled():
                try:
                    self._cur_func.restore_user_description()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _merge(self):
        """
        Merge current public description into the user's description.
        """
        if self._is_pointing_at_a_function():
            if self._is_handled():
                try:
                    self._cur_func.merge_public_to_users()
                except Exception as e:
                    print "REDB: Unexpected exception thrown:"
                    print e

    def _settings(self):
        """
        Change configurations.
        """
        self._plugin_configuration.change_config()

#-----------------------------------------------------------------------------
# Client Interface Utilities
#-----------------------------------------------------------------------------
    def _is_handled(self):
        return self._cur_func != None

    def _is_admissable(self):
        """
        Filters out irrelevant function.
        """
        flags = idc.GetFunctionFlags(self._start_addr)
        if (flags & (idc.FUNC_THUNK | idc.FUNC_LIB)):
            err_str = "REDB: function has been identified by IDA as a "
            err_str += "thunk or a library function and therefore will "
            err_str += "not be handled."
            print err_str
            return False
        else:
            if (len(list(idautils.FuncItems(self._start_addr))) < \
                MIN_INS_PER_HANDLED_FUNCTION):
                err_str = "REDB: function has too few instructions "
                err_str += "and therefore will not be handled."
                print err_str
                return False
        return True

    def _add_function(self):
        """
        Adds a function to handled functions dictionary.
        """
        self._cur_func = redb_function.REDBFunction(self._start_addr,
                                                    self._string_addresses,
                                                    self._imported_modules,
                                                    self._plugin_configuration)
        self._redb_functions[str(self._start_addr)] = self._cur_func

        redb_client_utils.Tag(self._start_addr).add_tag(user=True)

    def _is_pointing_at_a_function(self):
        if self._currently_pointing_at_a_function:
            return True
        else:
            print "REDB: Not pointing at a function."
            return False

    def _request_one(self):
        """
        Request descriptions for a function.
        """
        if self._is_pointing_at_a_function():
            if (not self._is_handled()):
                if (self._is_admissable()):
                    self._add_function()
                else:
                    return
            idaapi.show_wait_box("Requesting...")
            try:
                self._cur_func.request_descriptions()
            except Exception as e:
                print "REDB: Unexpected exception thrown while requesting:"
                print e
            idaapi.hide_wait_box()

    def _request_neighbors(self):
        """
        Applying 'request' on immediate neighbors.
        """
        # CodeRefsTo current function
        neighbors_list = list(idautils.CodeRefsTo(self._start_addr, 0))

        # CodeRefsFrom current function
        for item in self._cur_func._func_items:
            neighbors_list += list(idautils.CodeRefsFrom(item, 0))

        # Prompting the user for desired action
        prompt_string = (str(len(neighbors_list)) +
                         " neighbor functions were found.\n " +
                         "Request descriptions for these functions?")
        answer = idc.AskYN(-1, prompt_string)

        # Request neighbor function
        if (answer):
            for func_addr in neighbors_list:
                client = ClientAction(self._redb_item, self._arg, func_addr,
                                      self._plugin_configuration)
                client._request_one()
