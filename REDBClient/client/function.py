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
from descriptions import DescriptionUtils

MIN_INS_PER_HANDLED_FUNCTION = 5


class Function:
    """
    Represents a handled function.
    """
    def __init__(self, first_addr, string_addresses):
        self._first_addr = first_addr
        self._func_items = list(idautils.FuncItems(self._first_addr))
        self._num_of_func_items = len(self._func_items)
        self._string_addresses = string_addresses
        self._public_descriptions = []
        self._history_buffer = []
        self._attributes = attributes.FuncAttributes(self._first_addr,
                                                     self._func_items,
                                                     self._string_addresses).\
                                                     get_attributes()

    def request_descriptions(self):
        # Making room for new descriptions
        self._public_descriptions = []

        # Preparing Post
        post = utils.Post()
        post.add_data('type', 'request')
        post.add_data('attributes', self._attributes)

        # Requesting
        idaapi.show_wait_box("Requesting...")
        res_data = post.send()
        idaapi.hide_wait_box()

        # Handling response
        if isinstance(res_data, str):  # a message from the server
            return res_data
        elif isinstance(res_data, list):
            for description in res_data:
                self._add_description(description)
            return "Received " + str(len(res_data)) + " descriptions."
        else:
            return "Error: Illegal response format."

    def submit_description(self):
        # Preparing Post
        post = utils.Post()
        post.add_data('type', 'submit')
        post.add_data('attributes', self._attributes)
        cur_desc = descriptions.DescriptionUtils.get_all(self._first_addr)
        post.add_data('description', cur_desc)

        # Submitting
        idaapi.show_wait_box("Submitting...")
        res_data = post.send()
        idaapi.hide_wait_box()

        # Handling response
        if isinstance(res_data, str):  # a message from the server
            return res_data
        else:
            return "Error: Illegal response format."

    def show_description_by_index(self, index):
        desc_data = {'data': DescriptionUtils.get_all(self._first_addr)}
        history_desc = descriptions.Description(self._first_addr,
                                 self._num_of_func_items,
                                 desc_data)
        history_row = {}
        history_row['desc'] = history_desc
        selected_description = self._public_descriptions[index]
        history_row['prev_desc_details'] = (selected_description.created_by +
                                            '`s' + " description")
        self._history_buffer.append(history_row)
        selected_description.show()
        return "Showing description number " + str(index)

    def show_history_item_by_index(self, index):
        desc_data = {'data': DescriptionUtils.get_all(self._first_addr)}
        history_desc = descriptions.Description(self._first_addr,
                                 self._num_of_func_items,
                                 desc_data)
        history_row = {}
        history_row['desc'] = history_desc
        history_row['prev_desc_details'] = ("local history item no." +
                                            str(index))
        self._history_buffer.append(history_row)
        selected_description = self._history_buffer[index]
        selected_description['desc'].show()
        return "Showing description number " + str(index)

#==============================================================================
# Utility methods
#==============================================================================
    def _add_description(self, description):
        self._public_descriptions.append(descriptions.\
                                      Description(self._first_addr,
                                                  len(self._func_items),
                                                  description))

    def _add_description_to_history_buffer(self, description):
            self._history_buffer.append(descriptions.\
                                  Description(self._first_addr,
                                              len(self._func_items),
                                              description))

    def _is_lib_or_thunk(self, startEA):
        flags = idc.GetFunctionFlags(startEA)
        return (flags & (idc.FUNC_THUNK | idc.FUNC_LIB))
