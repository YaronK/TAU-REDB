"""
This module contains the main class inheriting from idaapi.plugin_t.
"""

# related third party imports
import idaapi
import idc
import idautils

# local application/library specific imports
import action
import utils


#==============================================================================
# REDB Class
#==============================================================================
class REDB (idaapi.plugin_t):
    """
    Main class loaded by IDA, inherits from idaapi.plugin_t.
    """
    flags = None
    comment = "REDB Plugin"
    help = "See site for help"
    wanted_name = ""
    wanted_hotkey = ""

    def init(self):
        self._executable = Executable()
        self._callback_functions = utils._create_callback_func_table()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This function is called by IDA when the user uses one of the plugins'
        hotkeys.
        """
        action.Action(self._executable, self._callback_functions, arg,
                      idc.ScreenEA()).run()

    def term(self):
        """
        Called by IDA upon termination.
        """
        self._executable.term()


def PLUGIN_ENTRY():
    return REDB()


class Executable:
    def __init__(self):
        self._make_run_prepereations()
        # Main dictionary holding all handled functions information.
        # The keys are the functions' first addresses.
        # The values are REDB_Functions - one for each handled function.
        self._redb_functions = {}
        self._string_addresses = []
        self._imported_modules = []

    def _make_run_prepereations(self):
        """
        Preparations which take place in the loading process.
        """
        idaapi.show_wait_box("REDB Plugin is loading, please wait...")

        utils._backup_idb_file()
        utils.Configuration.assert_config_file_validity()
        self._collect_string_addresses()
        self._collect_imported_modules()

        print "REDB: Plugin loaded, press Ctrl-Shift-I for a list of commands."

        idaapi.hide_wait_box()

    def _collect_string_addresses(self):
        """
        Initializing self._string_addresses to be a list holding all of the
        executables' string addresses.
        """
        self._string_addresses = [string.ea for string in idautils.Strings()]

    def _collect_imported_modules(self):
        """
        Initializing self._imported_modules to be a list holding all of the
        executables' modules and functions.
        """
        self._imported_modules = \
            utils.ImportsAndFunctions().collect_imports_data()

    def term(self):
        idaapi.hide_wait_box()

        # Restore user descriptions so that they will be saved by IDA.
        for function in self._redb_functions.values():
            function.restore_user_description()
