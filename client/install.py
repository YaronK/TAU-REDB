"""
Plugin installation.

In cmd, as Administrator, enter:
"<python.exe full path> <client folder full path>\install.py"

A propmt will be given:
"IDA Dir Path?"

Enter the location in which IDA is at your computer, for example:
"C:\Program Files (x86)\IDA 6.3"
"""

# standard library imports
import os
import shutil
import sys

CALLBACK_FUNCTIONS = [("Information", "Ctrl-Shift-I", "information"),
                      # interaction with the server
                      ("Submit_Current", "Ctrl-Shift-S", "submit_current"),
                      ("Request_Current", "Ctrl-Shift-R", "request_current"),
                      # description browsing
                      ("Next_Public_Description", "Ctrl-Shift-.",
                       "next_public_description"),
                      ("Previous_Public_Description", "Ctrl-Shift-,",
                       "previous_public_description"),
                      ("Restore_My_Description", "Ctrl-Shift-U",
                       "restore_my_description"),
                      ("Merge_Public_Into_Users", "Ctrl-Shift-M",
                       "merge_public_into_users"),
                      # settings
                      ("Settings", "Ctrl-Shift-O", "settings"),
                      # Debug - add these two tuples to CALLBACK_FUNCTIONS to
                      # enable mass submitting and requesting.
                      # ("Submit_All", "Ctrl-Shift-Z", "_submit_all"),
                      # ("Request_All", "Ctrl-Shift-X", "_request_all"),
                     ]

def is_admin(path):
    hostsFileBackup = file(path).read()
    try:
        filehandle = open(path, 'w')
        filehandle.write(hostsFileBackup)
        filehandle.close()
        return True
    except IOError:
        return False

def main():
    ida_dir_path = raw_input("IDA Dir Path?")

    if not os.path.exists(ida_dir_path):
        print "Directory does not exist"
        return "Fail"

    ida_plugins_cfg_file_path = os.path.join(ida_dir_path, "plugins",
                                             "plugins.cfg")

    if not os.path.exists(ida_plugins_cfg_file_path):
        print "plugins.cfg does not exist"
        return "Fail"

    if not is_admin(ida_plugins_cfg_file_path):
        print "Not an administrator."
        print ("In cmd, as administrator," +
               "give python.exe this script as an argument.")
        return "Fail"

    install_file_dir_path = os.path.dirname(os.path.realpath(sys.argv[0]))  # os.getcwd()
    print install_file_dir_path
    # print (install_file_dir_path + '\n')
    plugin_path = os.path.join(install_file_dir_path, "Client", "redb_main.py")

    filehandle = open(ida_plugins_cfg_file_path, 'a')
    line_to_be_added = '\n;REDB CALLBACK_FUNCTIONS PARSER: ENTER'
    filehandle.write(line_to_be_added)
    for i in range(len(CALLBACK_FUNCTIONS)):
        function = CALLBACK_FUNCTIONS[i]
        line_to_be_added = ("\n" +
                            function[0] +  # callback name
                            "\t" +
                            plugin_path +
                            "\t" +
                            function[1] +  # Shortcut combo
                            "\t" +
                            str(i) +
                            "\tSILENT")
        filehandle.write(line_to_be_added)

    line_to_be_added = "\n"
    filehandle.write(line_to_be_added)
    line_to_be_added = ';REDB CALLBACK_FUNCTIONS PARSER: EXIT\n'
    filehandle.write(line_to_be_added)
    filehandle.close()

    return "Success"

if __name__ == "__main__":
    print main()
    raw_input("Goodbye")
