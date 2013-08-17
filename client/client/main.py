"""
This module contains the main class inheriting from idaapi.plugin_t.
"""
import action
import idaapi

GUI_ENABLED = True

try:
    import pygtk
    pygtk.require('2.0')
except:
    GUI_ENABLED = False

try:
    # Prevent importing when already imported
    try:
        gtk  # @UndefinedVariable
    except:
        import gtk  # @UnusedImport
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
        if GUI_ENABLED:
            self.actions = action.GuiActions(gtk)
        else:
            print "GUI disabled."
            self.actions = action.HotkeyActions()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.actions.action(arg)

    def term(self):
        # self.actions.term()  #TODO: check if neccessary
        pass


def PLUGIN_ENTRY():
    return REDB()
