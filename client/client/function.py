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
from descriptions import Description, DescriptionUtils

MIN_INS_PER_HANDLED_FUNCTION = 5


class Function:
    """
    Represents a handled function.
    """
    def __init__(self, first_addr, string_addresses, imported_modules):
        self._first_addr = first_addr
        self._func_items = list(idautils.FuncItems(self._first_addr))
        self._num_of_func_items = len(self._func_items)
        self._imported_modules = imported_modules
        self._string_addresses = string_addresses
        self._public_descriptions = []
        self._history_buffer = []
        self._attributes = attributes.FuncAttributes(self._first_addr,
                                                     self._func_items,
                                                     self._string_addresses,
                                                     self._imported_modules).\
                                                     get_attributes()

    def request_descriptions(self):
        idaapi.show_wait_box("Requesting...")

        self._public_descriptions = []

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
            if isinstance(response, str):
                result = response
            else:
                for description in response:
                    self._add_description(description)
                result = "Received " + str(len(response)) + " descriptions."

        idaapi.hide_wait_box()
        return result

    def submit_description(self):
        idaapi.show_wait_box("Submitting...")

        if self._is_lib_or_thunk(self._first_addr):
            return "Lib and thunk functions are not admissible."
        elif MIN_INS_PER_HANDLED_FUNCTION > self._num_of_func_items:
            return "Short functions are not admisible."

        host = utils.Configuration.get_option('host')
        cur_desc = descriptions.DescriptionUtils.get_all(self._first_addr)
        data = {"attributes": self._attributes, "description": cur_desc}
        query = utils.ServerQuery(query_type="submit",
                    username=utils.Configuration.get_option('username'),
                    password=utils.Configuration.get_option('password'),
                    data_dict=data).to_dict()

        result = utils.post_non_serialized_data(query, host)

        idaapi.hide_wait_box()
        return result

    def show_description_by_index(self, index):
        desc_data = {'data': DescriptionUtils.get_all(self._first_addr)}
        history = descriptions.Description(self._first_addr,
                                 self._num_of_func_items,
                                 desc_data)
        self._history_buffer.append(history)
        self._public_descriptions[index].show()
        return "Showing description number " + str(index)

    def show_history_item_by_index(self, index):
        desc_data = {'data': DescriptionUtils.get_all(self._first_addr)}
        history = descriptions.Description(self._first_addr,
                                 self._num_of_func_items,
                                 desc_data)
        self._history_buffer.append(history)
        self._history_buffer[index].show()
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
