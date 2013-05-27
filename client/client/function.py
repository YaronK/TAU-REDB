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
import idaapi
import idc

MIN_INS_PER_HANDLED_FUNCTION = 5


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
        idaapi.show_wait_box("Requesting...")

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
            result = "No reply or an error occurred!"
        else:
            for description in response:
                self._add_description(description)
            result = "Received " + str(len(response)) + " descriptions."

        idaapi.hide_wait_box()
        return result

    def submit_description(self):
        idaapi.show_wait_box("Submitting...")

        if not self._is_cur_user_desc():
            result = "Can't submit a public description."
        elif self._is_lib_or_thunk(self._first_addr):
            result = "Lib and thunk functions are not admissible."
        elif MIN_INS_PER_HANDLED_FUNCTION > len(self._func_items):
            result = "Short functions are not admisible."
        else:
            self._cur_description().save_changes()

            host = utils.Configuration.get_option('host')
            data = {"attributes": self._attributes,
                "description": self._cur_description().data}
            query = utils.ServerQuery(query_type="submit",
                        username=utils.Configuration.get_option('username'),
                        password=utils.Configuration.get_option('password'),
                        data_dict=data).to_dict()

            result = utils.post_non_serialized_data(query, host)

        idaapi.hide_wait_box()
        return result

    def show_description_by_index(self, index):
        if not self._public_desc_exist():
            return "No public descriptions available."
        if index >= self.num_of_decriptions():
            return "Bad description index."
        if self._is_cur_user_desc():
            self._save_changes()
        self.cur_index = index
        self.get_descripition_by_index(index).show()
        return "Showing description number " + str(index)

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
        return self.get_descripition_by_index(self.cur_index).merge_cur_func()

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
        return (self.cur_index + 1) % self.num_of_decriptions()

    def _get_prev_desc_index(self):
        return (self.cur_index - 1) % self.num_of_decriptions()

    def _is_cur_user_desc(self):
        return self.cur_index == 0

    def _public_desc_exist(self):
        return len(self._descriptions) > 1

    def _cur_description(self):
        return self._descriptions[self.cur_index]

    def _discard_public_descriptions(self):
        self._descriptions = self._descriptions[0:1]

    def _is_lib_or_thunk(self, startEA):
        flags = idc.GetFunctionFlags(startEA)
        return (flags & (idc.FUNC_THUNK | idc.FUNC_LIB))
