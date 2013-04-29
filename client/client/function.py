"""
This module contains functions that collect some useful data
from the executable.
"""

# local application/library specific imports
import descriptions
import attributes
import utils

# related third party imports
import idautils


class Function:
    """
    Represents a handled function.
    """
    def __init__(self, first_addr, string_addresses, imported_modules):
        self._first_addr = first_addr
        self._func_items = list(idautils.FuncItems(self._first_addr))
        self._imported_modules = imported_modules
        self._string_addresses = string_addresses
        self._descriptions = [descriptions.Description(self._first_addr)]
        self._desc_index = 0

        self._attributes = attributes.FuncAttributes(self._first_addr,
                                                     self._func_items,
                                                     self._string_addresses,
                                                     self._imported_modules).\
                                                     get_attributes()

    def request_descriptions(self):
        """
        Request descriptions for a function.
        """
        # Reset public descriptions
        self.restore_user_description()
        self._descriptions = list(self._descriptions[0])

        host = utils.Configuration.get_option('host')

        request_dict = {"type": "request",
                        "attributes": self._attributes}

        response = utils.post_non_serialized_data(request_dict, host)

        if response:
            for suggested_description_dict in response.suggested_descriptions:
                desc = descriptions.Description(self._first_addr,
                                                suggested_description_dict)
                self._descriptions.append(desc)

            num_of_rec_desc = len(response.suggested_descriptions)
            print ("REDB: Received " + str(num_of_rec_desc) +
                   " public descriptions.")

            if num_of_rec_desc:
                self.next_description()
        else:
            print "REDB: No reply or an error occurred!"

    def submit_description(self):
        """
        Submits the user's description.
        """
        if self._is_cur_user_desc():
            host = utils.Configuration.get_option('host')
            self._cur_description().save_changes()

            description_data = \
                {"user_name": utils.Configuration.get_option('username'),
                 "password_hash": utils.Configuration.get_option('password'),
                 "data": self._cur_description().description_data}

            # TODO: password should be passed in submit dictionary
            submit_dict = {"type": "submit",
                           "attributes": self._attributes,
                           "description_data": description_data}

            utils.post_non_serialized_data(submit_dict, host)
        else:
            print "REDB: Can't submit a public description."

    def next_description(self):
        """
        View next public description.
        """
        if self._public_desc_exist():
            if self._is_cur_user_desc():
                self._descriptions[self._desc_index].save_changes()
            self._desc_index = (self._desc_index + 1) % len(self._descriptions)
            self._descriptions[self._desc_index].show()
        else:
            print "REDB: You don't have any public descriptions!"

    def previous_description(self):
        """
        View previous public description.
        """
        if self._public_desc_exist():
            if self._is_cur_user_desc():
                self._descriptions[self._desc_index].save_changes()
            self._desc_index = (self._desc_index - 1) % len(self._descriptions)
            self._descriptions[self._desc_index].show()
        else:
            print "REDB: You don't have any public descriptions!"

    def restore_user_description(self):
        """
        Restore the user's description.
        """
        if not self._is_cur_user_desc():
            self._desc_index = 0
            self._descriptions[self._desc_index].show()
        else:
            print "REDB: This is the user's description."

    def merge_public_to_users(self):
        """
        Merge current public description into the user's description.
        """
        if self._is_cur_user_desc():
            print "REDB: Current Description IS the user's description."
        else:
            self._current_description.remove_desc()

            self._set_current_description(self._user_description)
            self._current_description.show_desc()
            self._public_descriptions[self._public_desc_index].\
                                                        merge_into_users()
            print ("REDB: Description No." +
                   str(self._public_desc_index + 1) +
                   " was merged into the user's description.")

#==============================================================================
# Utility methods
#==============================================================================

    def _is_cur_user_desc(self):
        return self._desc_index == 0

    def _public_desc_exist(self):
        return len(self._descriptions) > 1

    def _cur_description(self):
        return self._descriptions[self._desc_index]
