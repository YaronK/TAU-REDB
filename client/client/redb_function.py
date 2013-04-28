"""
This module contains a class representing a handled function.
"""
# related third party imports
import idautils

# local application/library specific imports
import redb_client_descriptions
import redb_attributes

import json


class REDBFunction:
    """
    Represents a handled function.
    """
    def __init__(self, first_addr, string_addresses, imported_modules,
                 plugin_configuration):
        self._first_addr = first_addr
        self._func_items = list(idautils.FuncItems(self._first_addr))
        self._imported_modules = imported_modules
        self._string_addresses = string_addresses
        self._plugin_configuration = plugin_configuration

        self._public_descriptions = []
        self._public_desc_index = None
        self._num_of_pub_desc = 0

        self._user_description = \
            redb_client_descriptions.LocalDescription(self._first_addr)
        self._user_description.load_users()
        self._current_description = self._user_description

        # Get function attributes
        self._attributes = \
            redb_attributes.FuncAttributes(self._first_addr,
                                   self._func_items,
                                   self._string_addresses,
                                   self._imported_modules).get_attributes()
        self._description_data = {}
        self._description_data["user_name"] = \
            self._plugin_configuration.username
        self._description_data["password_hash"] = \
            self._plugin_configuration.pass_hash
        gc.collect()

    def request_descriptions(self):
        """
        Request descriptions for a function.
        """
        # Reset public descriptions
        self._public_descriptions = []

        host = self._plugin_configuration.host
        dumped_request_data = json.dumps({"type": "request",
                              "attributes": self._attributes})

        response = redb_client_com.send_request(dumped_request_data, host)

        if response != None:
            for suggested_description_dict in response.suggested_descriptions:
                # generate suggested description object
                # from suggested description dictionray recieved.
                suggested_description = \
                    redb_client_descriptions.SuggestedDecsription()
                suggested_description.from_dict(suggested_description_dict)

                # generate local description from suggested description.
                local_description = \
                    redb_client_descriptions.LocalDescription(self._first_addr)
                local_description.load_suggested(suggested_description)

                self._public_descriptions.append(local_description)

            self._num_of_pub_desc = len(self._public_descriptions)

            print ("REDB: Received " + str(self._num_of_pub_desc) +
                   " public descriptions.")

            if self._num_of_pub_desc:
                self._current_description.remove_desc()
                self._public_desc_index = 0
                self._current_description = \
                    self._public_descriptions[self._public_desc_index]
                self._current_description.\
                    show_desc(index=(self._public_desc_index + 1),
                              outof=self._num_of_pub_desc)
        else:
            print "REDB: No reply or an error occurred!"

    def submit_description(self):
        """
        Submits the user's description.
        """
        if self._is_cur_user_desc():
            self._set_current_description(self._user_description)

            self._description_data["data"] = \
                self._user_description._func_name_and_cmts

            dumped_submit_data = json.dumps({"type": "submit",
                                 "attributes": self._attributes,
                                 "description_data": self._description_data})
            host = self._plugin_configuration.host

            redb_client_com.send_submit(dumped_submit_data, host)
        else:
            print "REDB: Can't submit a public description."

    def next_description(self):
        """
        View next public description.
        """
        if self._public_desc_exist():
            self._current_description.remove_desc()

            self._determine_public_index(True)
            self._set_current_description(self.\
                              _public_descriptions[self._public_desc_index])

            self._current_description.\
                show_desc(index=(self._public_desc_index + 1),
                          outof=self._num_of_pub_desc)
        else:
            print "REDB: You don't have any public descriptions!"

    def previous_description(self):
        """
        View previous public description.
        """
        if self._public_desc_exist():
            self._current_description.remove_desc()

            self._determine_public_index(False)
            self._set_current_description(self.\
                              _public_descriptions[self._public_desc_index])

            self._current_description.\
                show_desc(index=(self._public_desc_index + 1),
                          outof=self._num_of_pub_desc)
        else:
            print "REDB: You don't have any public descriptions!"

    def restore_user_description(self):
        """
        Restore the user's description.
        """
        if not self._is_cur_user_desc():
            self._current_description.remove_desc()

            self._set_current_description(self._user_description)
            self._current_description.show_desc()
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
        return self._current_description == self._user_description

    def _public_desc_exist(self):
        return (len(self._public_descriptions) != 0)

    def _out_of_pub_desc_range(self):
        return ((self._public_desc_index >= self._num_of_pub_desc) or
                (self._public_desc_index == -1))

    def _determine_public_index(self, next_desc):
        """
        Determine the description index that is to be shown.
        """
        if self._is_cur_user_desc():
            if next_desc:
                # first public description
                self._public_desc_index = 0
            else:
                # last public description
                self._public_desc_index = self._num_of_pub_desc - 1
        else:  # current description is public
            if next_desc:
                self._public_desc_index += 1
            else:
                self._public_desc_index -= 1
            if self._out_of_pub_desc_range():
                if next_desc:
                    # first public description
                    self._public_desc_index = 0
                else:
                    # last public description
                    self._public_desc_index = self._num_of_pub_desc - 1

    def _set_current_description(self, desc):
        self._current_description.remove_desc()
        self._current_description = desc
