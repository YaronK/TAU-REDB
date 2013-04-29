import idc
from idautils import FuncItems
import idaapi


class Description:
    SUGGESTED_DESCRIPTION_DICT_KEYS = ["description_data",
                                       "matching_grade",
                                       "can_be_embedded",
                                       "by_user",
                                       "date"]

    def __init__(self, first_addr, suggested_description=None):
        self.first_addr = first_addr

        if suggested_description:
            for key in Description.SUGGESTED_DESCRIPTION_DICT_KEYS:
                setattr(self, key, suggested_description[key])
        else:
            self.can_be_embedded = True
            self.save_changes()

    def show(self):
        """
        deletes previous comments.
        """
        if self.can_be_embedded:
            DescriptionUtils.set_all(self.first_addr, self.description_data,
                                     append=None)

    def save_changes(self):
        self.description_data = DescriptionUtils.get_all(self.first_addr)


class DescriptionUtils:
    @classmethod
    def get_all(cls, start_addr):
        dic = {}
        dic["func_name"] = cls.get_func_name(start_addr)
        dic["comments"] = cls.get_all_comments(start_addr)
        dic["func_comments"] = cls.get_both_func_comments(start_addr)
        dic["stack_members"] = cls.get_stack_members(start_addr)
        return dic

    @classmethod
    def get_func_name(cls, start_addr):
        return idc.GetFunctionName(start_addr)

    @classmethod
    def get_all_comments(cls, start_addr):
        comments = cls.get_comments(start_addr, 0)
        comments += cls.get_comments(start_addr, 1)
        return comments

    @classmethod
    def get_comments(cls, start_addr, repeatable):
        return filter(None,
            [cls.get_one_comment_tuple(ea, start_addr, repeatable)
             for ea in FuncItems(start_addr)])

    @classmethod
    def get_one_comment_tuple(cls, real_ea, start_addr, repeatable):
        """
        Returns a tuple (offset, is-repeatable, string).
        If it does not exist returns None.
        """
        string = cls.get_one_comment(real_ea, repeatable)
        if string:
            return (real_ea - start_addr, repeatable, string)
        else:
            return None

    @classmethod
    def get_one_comment(cls, real_ea, repeatable):
        return idc.GetCommentEx(real_ea, repeatable)

    @classmethod
    def get_both_func_comments(cls, start_addr):
        comments = cls.get_func_comment(start_addr, 0)
        if comments:
            return (comments +
                    cls.get_func_comment(start_addr, 1))
        else:
            return cls.get_func_comment(start_addr, 1)

    @classmethod
    def get_func_comment(cls, start_addr, repeatable):
        """
        Returns a tuple (is-repeatable, string).
        If it does not exist returns None.
        """
        reg_cmt = idc.GetFunctionCmt(start_addr, repeatable)
        if reg_cmt:
            return (repeatable, reg_cmt)
        else:
            return None

    @classmethod
    def get_stack_members(cls, start_addr):
        """
        Generates and returns a list of stack members (variables and
        arguments).
        member := (offset in stack, name, size, flag, regular comment,
        repeatable comment)
        Excludes ' r' and ' s'.
        """
        stack = idc.GetFrame(start_addr)
        stack_size = idc.GetStrucSize(stack)
        name_set = set(idc.GetMemberName(stack, i) for i in xrange(stack_size))
        name_set -= set([' r', ' s', None])
        offset_set = set(idc.GetMemberOffset(stack, name) for name in name_set)
        member_get_data =\
            lambda offset: (offset,
                            idc.GetMemberName(stack, offset),
                            idc.GetMemberSize(stack, offset),
                            idc.GetMemberFlag(stack, offset),
                            idc.GetMemberComment(stack, offset, 0),
                            idc.GetMemberComment(stack, offset, 1))
        return map(member_get_data, offset_set)

    @classmethod
    def set_all(cls, start_addr, description_dict, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        func_name = description_dict["func_name"]
        comments = description_dict["comments"]
        func_comments = description_dict["func_comments"]
        stack_members = description_dict["stack_members"]

        if append is None:
            cls.remove_all_comments(start_addr)

        cls.set_func_name(start_addr, func_name)
        cls.set_stack_members(start_addr, stack_members)

        cls.set_comments(start_addr, comments, append)
        cls.set_both_func_comments(start_addr, func_comments, append)
        idaapi.refresh_idaview_anyway()

    @classmethod
    def set_func_name(cls, start_addr, func_name):
        idaapi.set_name(start_addr, func_name, idaapi.SN_NOWARN)

    @classmethod
    def set_stack_members(cls, start_addr, stack_members):
        """
        Setting member attributes should be done in a more delicate manner:
        Only set name and comment if member exists (same size, flags).
        We currently do not create new members.
        assumes member structure defined at GetStackMembers().
        """
        stack = idc.GetFrame(start_addr)
        member_filter_lambda =\
            lambda member: ((idc.GetMemberFlag(stack, member[0]) == member[3])
                            and
                            (idc.GetMemberSize(stack, member[0]) == member[2]))

        filtered_member_set = filter(member_filter_lambda, stack_members)

        member_set_data_lambda =\
            lambda member: (idc.SetMemberName(stack, member[0], member[1]),
                            idc.SetMemberComment(stack, member[0], 0,
                                                 member[4]),
                            idc.SetMemberComment(stack, member[0], 1,
                                                 member[5]))

        map(member_set_data_lambda, filtered_member_set)

    @classmethod
    def set_comments(cls, start_addr, comments, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        for (offset, repeatable, text) in comments:
            real_ea = start_addr + offset
            cls.set_one_comment(real_ea, text, repeatable, append)

    @classmethod
    def set_one_comment(cls, real_ea, text, repeatable, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        cur_comment = cls.get_one_comment(real_ea, repeatable)
        if append == True and cur_comment:
            text = cur_comment + "; " + text
        elif append == False and cur_comment:
            text += "; " + cur_comment
        if repeatable:
            idc.MakeRptCmt(real_ea, text)
        else:
            idc.MakeComm(real_ea, text)

    @classmethod
    def set_both_func_comments(cls, start_addr, func_comments, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        for (repeatable, text) in func_comments:
            cls.set_func_comment(start_addr, append, repeatable, text)

    @classmethod
    def set_func_comment(cls, start_addr, repeatable, text, append=None):
        """
        append => append to current if True, prepend to current if False,
        discard current if null.
        """
        cur_comment = cls.get_func_comment(start_addr, repeatable)
        if append == True and cur_comment:
            text = cur_comment + "; " + text
        elif append == False and cur_comment:
            text += "; " + cur_comment
        idc.SetFunctionCmt(start_addr, text, repeatable)

    @classmethod
    def remove_all_comments(cls, start_addr):
        for ea in FuncItems(start_addr):
            cls.set_one_comment(ea, "", 0)
            cls.set_one_comment(ea, "", 1)
            cls.set_func_comment(start_addr, 0, "")
            cls.set_func_comment(start_addr, 1, "")
