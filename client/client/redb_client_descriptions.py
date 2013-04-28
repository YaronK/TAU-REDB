"""
Description data types.
"""
# local application/library specific imports
from client.redb_client_utils import DescriptionUtils as DU


class Description:
    """
    A description for a specific local function. It is initiated either by
    loading a SuggestedDescription or by loading the user's own description.
    Each LocalDescription can be shown on screen. A LocalDescription initiated
    by loading a SuggestedDescription can be merged into the user's description
    if it can be embedded.
    """
    SUGGESTED_DESCRIPTION_DICT_KEYS = ["description_data",
                                       "matching_grade",
                                       "can_be_embedded",
                                       "by_user",
                                       "date"]

    def __init__(self, first_addr, suggested_description=None):

        self.first_addr = first_addr

        if suggested_description:
            self.is_user_description = False
            for key in Description.SUGGESTED_DESCRIPTION_DICT_KEYS:
                setattr(self, key, suggested_description[key])
        else:
            self.is_user_description = True
            self.can_be_embedded = True
            self.save_changes()

    def show(self):
        """
        deletes previous comments.
        """
        if self.can_be_embedded:
            DU.set_all(self.first_addr, self.description_data, append=None)

    def save_changes(self):
        self.description_data = DU.get_all(self.first_addr)
