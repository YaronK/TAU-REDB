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
        self._descriptions = [descriptions.Description(self._first_addr,
                                                       len(self._func_items))]
        self.cur_index = 0
        self._attributes = attributes.FuncAttributes(self._first_addr,
                                                     self._func_items,
                                                     self._string_addresses,
                                                     self._imported_modules).\
                                                     get_attributes()

    def request_descriptions(self):
        # Reset public descriptions
        self.restore_user_description()
        self._discard_public_descriptions()

        host = utils.Configuration.get_option('host')

        data = {"attributes": self._attributes}

        query = utils.ServerQuery(query_type="request",
                    username=utils.Configuration.get_option('username'),
                    password=utils.Configuration.get_option('password'),
                    data_dict=data).to_dict()

        response = utils.post_non_serialized_data(query, host)
        if not response:
            return "No reply or an error occurred!"

        for description in response:
            self._add_description(description)
        num_of_rec_desc = len(response)
        if num_of_rec_desc:
            self.show_next_description()
        return ("Received " + str(num_of_rec_desc) + " descriptions.")

    def submit_description(self):
        """
        Submits the user's description.
        """
        if not self._is_cur_user_desc():
            return "Can't submit a public description."

        host = utils.Configuration.get_option('host')
        self._cur_description().save_changes()

        data = {"attributes": self._attributes,
                "description": self._cur_description().data}

        query = utils.ServerQuery(query_type="submit",
                username=utils.Configuration.get_option('username'),
                password=utils.Configuration.get_option('password'),
                data_dict=data).to_dict()

        return utils.post_non_serialized_data(query, host)

    def show_description_by_index(self, index):
        if not self._public_desc_exist():
            return "No public descriptions available."
        if index >= self.num_of_decriptions():
            return "Bad description index."
        if self._is_cur_user_desc():
            self._save_changes()
        self.cur_index = index
        self.get_descripition_by_index(index).show()

    def get_descripition_by_index(self, index):
        return self._descriptions[index]

    def num_of_decriptions(self):
        return len(self._descriptions)

    def show_next_description(self):
        return self.show_description_by_index(self._get_next_desc_index())

    def show_prev_description(self):
        return self.show_description_by_index(self._get_prev_desc_index())

    def restore_user_description(self):
        if self._is_cur_user_desc():
            return "This is the user's description."
        return self.show_description_by_index(0)

    def merge_public_to_users(self):
        if self._is_cur_user_desc():
            return "This is the user's description."
        self.get_descripition_by_index(self.cur_index).merge()

#==============================================================================
# Utility methods
#==============================================================================
    def _add_description(self, description):
        self._descriptions.append(descriptions.\
                                      Description(self._first_addr,
                                                  len(self._func_items),
                                                  description))

    def _save_changes(self):
        self.get_descripition_by_index(self.cur_index).save_changes()

    def _get_next_desc_index(self):
        return (self.cur_index + 1) % self._num_of_descriptions()

    def _get_prev_desc_index(self):
        return (self.cur_index - 1) % self._num_of_descriptions()

    def _is_cur_user_desc(self):
        return self.cur_index == 0

    def _public_desc_exist(self):
        return len(self._descriptions) > 1

    def _cur_description(self):
        return self._descriptions[self.cur_index]

    def _discard_public_descriptions(self):
        self._descriptions = self._descriptions[0:1]
