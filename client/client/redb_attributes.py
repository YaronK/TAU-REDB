"""
This module contains holds the FuncAttributes class. An instance of this
class is created for each handled function.
"""

# standard library imports
import hashlib
import gc

# related third party imports
import idautils
import idc
import idaapi

# local application/library specific imports
import redb_client_utils

# Constants
ATTRS_COLLECTED_ONCE = {"first_addr": "_FirstAddr",
                        "exe_signature": "_ExeMd5",
                        "graph": "_GraphRep",
                        "frame_attributes": "_FrameAttrs"}

ATTR_COLLECTED_ITER = {"func_signature": "_FuncMd5",
                       "itypes": "_InsTypeList",
                       "strings": "_StrList",
                       "library_calls": "_LibCallsList",
                       "immediates": "_ImmList"}

ATTRIBUTES = ["first_addr",
              "func_signature",
              "frame_attributes",
              "itypes",
              "strings",
              "library_calls",
              "immediates",
              "exe_signature",
              "graph"]


#==============================================================================
# FuncAttributes Class
#==============================================================================
class FuncAttributes:
    """
    This class gathers all of the functions' attributes. It holds an instance
    of each attribute class. First it initializes the class and then calls the
    collect and extract functions in turn.
    some of the collect functions are called once, others are called for each
    instruction.

    first_addr -- the functions' first address
    func_items -- the functions' list on instruction addresses
    string_addresses -- addresses of executables' strings
    imported_modules - list of imported modules
    """
    def __init__(self, first_addr, func_items, string_addresses,
                 imported_modules):

        # Data required for Attributes extraction
        self._first_addr = first_addr
        self._func_items = func_items
        self._string_addresses = string_addresses
        self._imported_modules = imported_modules

        # At initalization, self._results is filled with all attributes
        # data.
        self._results = {}

        self._initialize_attributes()
        self._collect_all()
        self._extract_all()
        self._del_all_attr()

        gc.collect()

    def _initialize_attributes(self):
        """
        Initializes attribute classes for attributes in ATTRS_COLLECTED_ONCE
        and ATTR_COLLECTED_ITER.
        """
        init_args = {"_func_items": self._func_items,
                     "_string_addresses": self._string_addresses,
                     "_imported_modules": self._imported_modules}
        for one_attribute in ATTRS_COLLECTED_ONCE:
            one_class_name = ATTRS_COLLECTED_ONCE[one_attribute]

            one_class = globals()[one_class_name]
            setattr(self, one_attribute, one_class(init_args))

        for one_attribute in ATTR_COLLECTED_ITER:
            one_class_name = ATTR_COLLECTED_ITER[one_attribute]
            one_class = globals()[one_class_name]
            setattr(self, one_attribute, one_class(init_args))

    def _collect_all(self):
        """
        Calls the attributes' Collect functions, once for attributes in
        ATTRS_COLLECTED_ONCE and for each instruction in for attributes in
        ATTR_COLLECTED_ITER.
        """
        collect_args = {"_first_addr": self._first_addr,
                        "_func_items": self._func_items}
        # Attributes that don't need to iterate instructions.
        for one_attribute in ATTRS_COLLECTED_ONCE.keys():
            getattr(self, one_attribute)._collect_data(collect_args)

        # Attributes which need to iterate instructions. Iterate over
        # instructions, while each attribute extracts data from it.
        for i in range(len(self._func_items)):

            func_item = self._func_items[i]
            ins = idautils.DecodeInstruction(func_item)
            ins_type = ins.itype
            ins_operands = redb_client_utils.collect_operands_data(func_item)

            collect_args["_func_item"] = func_item
            collect_args["_ins_type"] = ins_type
            collect_args["_ins_operands"] = ins_operands

            for one_attribute in ATTR_COLLECTED_ITER.keys():
                getattr(self, one_attribute)._collect_data(collect_args)

    def _extract_all(self):
        """
        Calls the attributes' Extract functions, keeps the results.
        """
        for one_attribute in ATTR_COLLECTED_ITER.keys():
            self._results[one_attribute] = getattr(self,
                                                   one_attribute)._extract()

        for one_attribute in ATTRS_COLLECTED_ONCE.keys():
            self._results[one_attribute] = getattr(self,
                                                   one_attribute)._extract()

    def _del_all_attr(self):
        """
        After saving the results, delete attribute classes.
        """
        for one_attribute in ATTR_COLLECTED_ITER.keys():
            attr = getattr(self, one_attribute)
            del attr

        for one_attribute in ATTRS_COLLECTED_ONCE.keys():
            attr = getattr(self, one_attribute)
            del attr

    def get_attributes(self):
        attr_dict = {}
        for attr_name in ATTRIBUTES:
            attr_dict[attr_name] = self._results[attr_name]
        return attr_dict


#==============================================================================
# Attribute Classes
#==============================================================================
class Attribute:
    """ Represents a single attribute. """
    def __init__(self, init_args):
        """ Initializes attribute class with init_args """
        for arg_name in init_args:
            setattr(self, arg_name, init_args[arg_name])

    def _collect_data(self, collect_args):
        """ Collects data necessary for attribute. """
        for arg_name in collect_args:
            setattr(self, arg_name, collect_args[arg_name])

    def _extract(self):
        """ Return collected data. """
        pass


#==============================================================================
# General attributes
#==============================================================================
class _FirstAddr(Attribute):
    """
    The function's first address.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._addr = None

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self._addr = self._first_addr

    def _extract(self):
        return self._addr


class _ExeMd5(Attribute):
    """
    The executable's md5 signature.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._exe_md5 = None

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        try:
            exe_file_path = idc.GetInputFilePath()
            md5_obj = hashlib.md5(open(exe_file_path).read())
            self._exe_md5 = md5_obj.hexdigest()
        except:  # exe does not exist.
            self._exe_md5 = ""

    def _extract(self):
        return self._exe_md5


class _FrameAttrs(Attribute):
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._frame_attrs = {}

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        first_addr = self._first_addr
        self._frame_attrs["FrameLvarSize"] = idc.GetFrameLvarSize(first_addr)
        self._frame_attrs["FrameRegsSize"] = idc.GetFrameRegsSize(first_addr)
        self._frame_attrs["FrameArgsSize"] = idc.GetFrameArgsSize(first_addr)
        self._frame_attrs["FrameSize"] = idc.GetFrameSize(first_addr)

    def _extract(self):
        return self._frame_attrs


#==============================================================================
# Instruction-related attributes
#==============================================================================
class _InsNum(Attribute):
    """
    The number of instructions in the function.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._ins_num = None

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self._ins_num = len(self._func_items)

    def _extract(self):
        del self._func_items
        return self._ins_num


class _FuncMd5(Attribute):
    """
    The whole function's MD5 hash.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._hash_string = ""
        self._to_be_hashed = hashlib.md5()

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self._to_be_hashed.\
            update(str(redb_client_utils.\
                            instruction_data(self._func_item)))

    def _extract(self):
        self._hash_string = str(self._to_be_hashed.hexdigest())
        del self._to_be_hashed
        return self._hash_string


class _InsTypeList (Attribute):
    """
    A list of instruction types.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._itype_list = []

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self._itype_list.append(self._ins_type)

    def _extract(self):
        return self._itype_list


#==============================================================================
# Strings-related attributes
#==============================================================================
class _StrList(Attribute):
    """
    A list of the strings which appear in the function.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._list_of_strings = []

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        for data_ref in list(idautils.DataRefsFrom(self._func_item)):
            if data_ref in self._string_addresses:
                str_type = idc.GetStringType(data_ref)
                if idc.GetStringType(data_ref) is not None:
                    string = idc.GetString(data_ref, -1, str_type)
                self._list_of_strings.append(string)

    def _extract(self):
        del self._string_addresses
        return self._list_of_strings


#==============================================================================
# Library calls-related attributes
#==============================================================================
class _LibCallsList(Attribute):
    """
    A list containing the lib call names which occur in a function.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._lib_calls_list = []

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        func_item = self._func_item
        code_refs_from_list = \
            list(idautils.CodeRefsFrom(func_item, False))

        for code_ref in code_refs_from_list:
            is_loaded_dynamically = False
            is_library_function = False
            called_function_name = ""

            if (idc.GetFunctionFlags(code_ref) == -1):
                # Find code_ref in functions that are imported dynamically
                for imported_module in self._imported_modules:
                    if code_ref in imported_module.get_addresses():
                        is_loaded_dynamically = True
                        break
            else:
                # get_func(code_ref) != get_func(func_item) ->
                # do not include coderefs to self.
                if ((idc.GetFunctionFlags(code_ref) & idaapi.FUNC_LIB) != 0 and
                    idaapi.get_func(code_ref) != idaapi.get_func(func_item)):
                    # code_ref is imported statically
                    is_library_function = True

            # Data is gathered only for library functions or Imports.
            if (is_library_function or is_loaded_dynamically):
                # get name
                called_function_name = idc.NameEx(func_item, code_ref)

                # include in attribute
                self._lib_calls_list.append(called_function_name)

    def _extract(self):
        del self._imported_modules
        return self._lib_calls_list


#==============================================================================
# Immediates-realted attributes
#==============================================================================
class _ImmList (Attribute):
    """
    A list of immediate values.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._list_of_pairs = []

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        for one_op in self._ins_operands:
            if ((one_op[0] in [5, 6, 7]) and
                (one_op[1] not in list(idautils.\
                    CodeRefsFrom(self._func_item, True)))):
                op = one_op[1]
                self._list_of_pairs.append(op)

    def _extract(self):
        return self._list_of_pairs


#==============================================================================
# Control-Flow Graph-related attribute
#==============================================================================
class _GraphRep (Attribute):
    """
    A representation of the function's control-flow.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self.block_bounds = None
        self.edges = []  # 2-tuples of numbers. edges.
        self.signature = []  # control flow graph signature

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self.func_flow_chart = \
            idaapi.FlowChart(f=idaapi.get_func(collect_args["_first_addr"]))
        self.block_bounds = [None] * self.func_flow_chart.size
        for basic_block in self.func_flow_chart:
            start_index = self._func_items.index(basic_block.startEA)
            if basic_block.endEA in self._func_items:
                end_index = self._func_items.index(basic_block.startEA) - 1
            else:   # last block
                end_index = len(self._func_items) - 1
            self.block_bounds[basic_block.id] = (start_index, end_index)

            for basic_block_neighbour in basic_block.succs():
                self.edges.append((basic_block.id, basic_block_neighbour.id))

    def _extract(self):
        return (self.block_bounds, self.edges)
