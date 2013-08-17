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
                        "exe_name",
                        "graph",
                        "frame_attributes"]

ATTR_COLLECTED_ITER = ["func_signature",
                       "func_name",
                       "itypes",
                       "strings",
                       "calls",
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
    """
    def __init__(self, first_addr, func_items, string_addresses):
        # Data required for Attributes extraction
        self._first_addr = first_addr
        self._func_items = func_items
        self._string_addresses = string_addresses

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
                     "_string_addresses": self._string_addresses}
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


class exe_name(Attribute):
    """
    The executable's md5 signature.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._exe_name = None

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self._exe_name = str(idc.GetInputFile())

    def _extract(self):
        return self._exe_name


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


class func_name(Attribute):
    """
    The function's name.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._func_name = None

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        self._func_name = str(idc.GetFunctionName(self._first_addr))

    def _extract(self):
        return self._func_name


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


class calls(Attribute):
    """
    A list containing names of functions called within our function.
    """
    def __init__(self, init_args):
        Attribute.__init__(self, init_args)
        self._calls_dict = {}

    def _collect_data(self, collect_args):
        Attribute._collect_data(self, collect_args)
        func_item = self._func_item
        refs = list(idautils.CodeRefsFrom(func_item, False))

        if refs:
            dest = refs[0]
            if dest in self._func_items:  # internal
                if dest != self._first_addr:  # not recursive
                    return
            index = self._func_items.index(self._func_item)
            self._calls_dict[index] = idc.GetTrueName(dest)

    def _extract(self):
        return self._calls_dict


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
        self.dist_from_root = {}  # 2-tuples of node and its distance from root

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

        self.dist_from_root = \
            self._breadth_first_search(self.func_flow_chart)

    def _breadth_first_search(self, flow_chart):
        # TODO: assign more indicative names:
        # v -> root?
        # nodes -> accessible_nodes / accessible_from_root
        # TODO: using Queue would simplify the code
        # TODO: inaccessible nodes should have distance != 0 (root is 0)
        result = {}
        result[0] = 0
        accessible_nodes = []
        marked = []
        v = flow_chart[0]
        marked.append(v.id)
        i = 1

        # 'nodes' holds only accessible nodes from root
        for node in flow_chart:
            for n in node.succs():
                accessible_nodes.append(n.id)

        accessible_nodes = list(set(accessible_nodes))

        while accessible_nodes:
            for node in v.succs():
                if node.id not in marked:
                    result[node.id] = result[v.id] + 1
                    marked.append(node.id)
            try:
                v = flow_chart[marked[i]]
            except:
                # for all inaccessible nodes from root, define '-1' distance
                for i in range(flow_chart.size):
                    if i not in result:
                        result[i] = -1
                return result
            if (v.id in accessible_nodes):
                accessible_nodes.remove(v.id)
                i += 1
        # for all inaccessible nodes define '-1' distance from root
        for i in range(flow_chart.size):
            if i not in result:
                result[i] = -1
        return result

    def _extract(self):
        return {"block_bounds": self.block_bounds,
                "edges": self.edges,
                "dist_from_root": self.dist_from_root}
