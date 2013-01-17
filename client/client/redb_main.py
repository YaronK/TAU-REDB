"""
This module contains the main class inheriting from idaapi.plugin_t.
"""

# related third party imports
import idaapi

# local application/library specific imports
import redb_action
import redb_item
import idc


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
        self._redb_item = redb_item.REDBItem()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This function is called by IDA when the user uses one of the plugins'
        hotkeys.
        """
        action = redb_action.ClientAction(self._redb_item, arg,
                                          idc.ScreenEA())
        action.run()

    def term(self):
        """
        Called by IDA upon termination.
        """
        self._redb_item.term()


def PLUGIN_ENTRY():
    return REDB()
