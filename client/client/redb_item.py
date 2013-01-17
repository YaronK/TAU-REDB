"""
This module contains functions that collect some useful data
from the executable.
"""

# related third party imports
import idaapi
import idautils

# local application/library specific imports
import redb_client_utils


#==============================================================================
# REDB Item
#==============================================================================
class REDBItem:
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
        print idaapi
        idaapi.show_wait_box("REDB Plugin is loading, please wait...")

        redb_client_utils._parse_config_file()
        self._collect_string_addresses()
        self._collect_imported_modules()

        print "REDB Plugin loaded, press Ctrl-Shift-I for a list of commands"

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
            redb_client_utils.ImportsAndFunctions().collect_imports_data()

    def term(self):
        idaapi.hide_wait_box()

        # Restore user descriptions so that they will be saved by IDA.
        for function in self._redb_functions.values():
            function.restore_user_description()

        # Remove all tags added by the plugin.
        for function in self._redb_functions:
            redb_client_utils.Tag(int(function)).remove_tag()
