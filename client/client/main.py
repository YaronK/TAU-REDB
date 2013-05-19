"""
This module contains the main class inheriting from idaapi.plugin_t.
"""
import action
import idaapi

GUI_ENABLED = True
GUI_MENU = None

try:
    import pygtk
    pygtk.require('2.0')
except:
    GUI_ENABLED = False

try:
    import gtk  # @UnusedImport
    import gtk.glade  # @UnusedImport
except:
    GUI_ENABLED = False


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
        action.Actions.initialize()
        action.GuiActions.initialize(gtk)
        # self._hotkey_callbacks = utils._create_callback_func_table()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if arg == 8:
            action.GuiActions.show_mainWindow()
        else:
            pass
            #action.HotkeyAction(self._executable, idc.ScreenEA(),
            #                    self._hotkey_callbacks, arg)

    def term(self):
        """
        Called by IDA upon termination.
        """
        pass


def PLUGIN_ENTRY():
    return REDB()
