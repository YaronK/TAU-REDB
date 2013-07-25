"""
This module contains holds the FuncAttributes class. An instance of this
class is created for each handled function.
"""

# standard library imports
import hashlib

# related third party imports
import idautils
import idc
import idaapi

# local application/library specific imports
import utils

# Constants
ATTRS_COLLECTED_ONCE = ["exe_signature",
                        "graph",
                        "frame_attributes"]

ATTR_COLLECTED_ITER = ["func_signature",
                       "itypes",
                       "strings",
                       "library_calls",
                       "immediates"]

ATTRIBUTES = ATTRS_COLLECTED_ONCE + ATTR_COLLECTED_ITER


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

    def _initialize_attributes(self):
        """
        Initializes attribute classes.
        """
        init_args = {"_func_items": self._func_items,
                     "_string_addresses": self._string_addresses,
                     "_imported_modules": self._imported_modules}
        for one_attribute in ATTRIBUTES:
            one_class = globals()[one_attribute]
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
        for one_attribute in ATTRS_COLLECTED_ONCE:
            getattr(self, one_attribute)._collect_data(collect_args)

        # Attributes which need to iterate instructions. Iterate over
        # instructions, while each attribute extracts data from it.
        for i in range(len(self._func_items)):
            func_item = self._func_items[i]
            ins = idautils.DecodeInstruction(func_item)
            ins_type = ins.itype
            ins_operands = utils.collect_operands_data(func_item)

            collect_args["_func_item"] = func_item
            collect_args["_ins_type"] = ins_type
            collect_args["_ins_operands"] = ins_operands

            for one_attribute in ATTR_COLLECTED_ITER:
                getattr(self, one_attribute)._collect_data(collect_args)

    def _extract_all(self):
        """
        Calls the attributes' Extract functions, keeps the results.
        """
        for one_attribute in ATTRIBUTES:
            self._results[one_attribute] = getattr(self,
                                                   one_attribute)._extract()

    def _del_all_attr(self):
        """
        After saving the results, delete attribute classes.
        """
        for one_attribute in ATTRIBUTES:
            attr = getattr(self, one_attribute)
            del attr

    def get_attributes(self):
        return self._results


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


class exe_signature(Attribute):
    """
    The executable's md5 signature.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._exe_md5 = None

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self._exe_md5 = str(idc.GetInputMD5())

    def _extract(self):
        return self._exe_md5


class frame_attributes(Attribute):
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._frame_attrs = {}

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        first_addr = self._first_addr
        self._frame_attrs["vars_size"] = idc.GetFrameLvarSize(first_addr)
        self._frame_attrs["regs_size"] = idc.GetFrameRegsSize(first_addr)
        self._frame_attrs["args_size"] = idc.GetFrameArgsSize(first_addr)
        self._frame_attrs["frame_size"] = idc.GetFrameSize(first_addr)

    def _extract(self):
        return self._frame_attrs


class func_signature(Attribute):
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
            update(str(utils.instruction_data(self._func_item)))

    def _extract(self):
        self._hash_string = str(self._to_be_hashed.hexdigest())
        return self._hash_string


class itypes(Attribute):
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


class strings(Attribute):
    """
    A list of the strings which appear in the function.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._dict_of_strings = {}

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)

        for data_ref in list(idautils.DataRefsFrom(self._func_item)):
            if data_ref in self._string_addresses:
                str_type = idc.GetStringType(data_ref)
                if idc.GetStringType(data_ref) is not None:
                    string = idc.GetString(data_ref, -1, str_type)
                    index = self._func_items.index(self._func_item)
                    self._dict_of_strings[index] = string

    def _extract(self):
        return self._dict_of_strings


class library_calls(Attribute):
    """
    A list containing the lib call names which occur in a function.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._lib_calls_dict = {}

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
                index = self._func_items.index(self._func_item)
                self._lib_calls_dict[index] = called_function_name

    def _extract(self):
        return self._lib_calls_dict


class immediates(Attribute):
    """
    A list of immediate values.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._immediates_dict = {}

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        for one_op in self._ins_operands:
            if ((one_op[0] in [5, 6, 7]) and
                (one_op[1] not in list(idautils.\
                    CodeRefsFrom(self._func_item, True)))):
                op = one_op[1]
                index = self._func_items.index(self._func_item)
                self._immediates_dict[index] = op

    def _extract(self):
        return self._immediates_dict


class graph(Attribute):
    """
    A representation of the function's control-flow.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)

        self.block_bounds = []
        self.edges = []  # 2-tuples of numbers. edges.
        self.signature = []  # control flow graph signature

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)

        self.func_flow_chart = \
            idaapi.FlowChart(f=idaapi.get_func(self._first_addr))
        for basic_block in self.func_flow_chart:
            if basic_block.startEA not in self._func_items:
                continue
            start_index = self._func_items.index(basic_block.startEA)
            if basic_block.endEA in self._func_items:
                end_index = self._func_items.index(basic_block.endEA) - 1
            else:  # last block
                end_index = len(self._func_items) - 1
            self.block_bounds.append((start_index, end_index))

            for basic_block_neighbour in basic_block.succs():
                self.edges.append((basic_block.id, basic_block_neighbour.id))

    def _extract(self):
        return {"block_bounds": self.block_bounds,
                "edges": self.edges}
