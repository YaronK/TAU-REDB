"""
Utilities for all the other modules.
"""
import traceback
import os
import functools
import graph
from ctypes import cdll
import time
import ctypes
import json


#==============================================================================
# Changing from unicode for compatibility.
#==============================================================================
def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


#==============================================================================
# Control-Flow Graph-related utilities
#==============================================================================
class CliquerGraph:
    DLL_DIR_PATH = os.path.dirname(__file__)
    DLL_FILE_PATH = os.path.join(DLL_DIR_PATH, 'CliquerReduced.dll')

    def __init__(self, n):
        """ n : number of vertices """
        self.lib = cdll.LoadLibrary(CliquerGraph.DLL_FILE_PATH)
        self.g = self.lib.graph_new(n)

    def add_edge(self, i, j):
        """
        i, j : vertices in [0..n-1]
        returns: 0 on success, -1 on failure
        """
        return self.lib.graph_add_edge_redb(self.g, i, j)

    def remove_edge(self, i, j):
        """
        i, j : vertices in [0..n-1]
        returns: 0 on success, -1 on failure
        """
        return self.lib.graph_remove_edge_redb(self.g, i, j)

    def set_vertex_weight(self, i, w):
        """
        i : vertex in [0..n-1]
        w: weight (of type int in c)
        returns: 0 on success, -1 on failure
        """
        return self.lib.graph_set_vertex_weight_redb(self.g, i, w)

    def __str__(self):
        return str(self.lib.graph_print(self.g))

    def clique_max_size(self, reorder=0):
        """
        reorder =
            0(no reordering)/"reorder_by_greedy_coloring"/"reorder_by_degree"
        returns: max_size on success, -1 on failure
        """
        if reorder not in [0, "reorder_by_greedy_coloring",
                           "reorder_by_degree"]:
            return -1
        if reorder:
            reorder = getattr(self.lib, reorder)

        opts = self.lib.clique_options_new_redb(reorder)
        max_size = self.lib.clique_max_size(self.g, opts)
        self.lib.clique_options_free_redb(opts)
        return max_size

    def clique_max_weight(self, reorder=0):
        if reorder not in [0, "reorder_by_greedy_coloring",
                           "reorder_by_degree"]:
            return -1
        if reorder:
            reorder = getattr(self.lib, reorder)

        opts = self.lib.clique_options_new_redb(reorder)
        max_weight = self.lib.clique_max_weight(self.g, opts)
        self.lib.clique_options_free_redb(opts)
        return max_weight

    def get_max_clique(self, reorder=0):
        """
        reorder =
            0(no reordering)/"reorder_by_greedy_coloring"/"reorder_by_degree"
        returns: max_size on success, -1 on failure
        """
        if reorder not in [0, "reorder_by_greedy_coloring",
                           "reorder_by_degree"]:
            return -1
        if reorder:
            reorder = getattr(self.lib, reorder)

        opts = self.lib.clique_options_new_redb(reorder)
        clique = self.lib.get_max_clique(self.g, opts)
        self.lib.clique_options_free_redb(opts)
        c_s = ctypes.c_char_p(clique)
        return json.loads(c_s.value)

    def free(self):
        self.lib.graph_free(self.g)

    def string_free_redb(self, string):
        self.lib.string_free_redb(string)


#==============================================================================
# Decorators
#==============================================================================
def log(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        print "enter: " + str(f.__name__)
        try:
            retval = f(*args, **kwargs)
            print "exit: " + str(f.__name__)
            return retval
        except Exception, e:
            # get traceback info to print out later
            print type(e).__name__
            for frame in traceback.extract_stack():
                print os.path.basename(frame[0]), str(frame[1])
            raise
    return wrapped


def log_timing():
    '''Decorator generator that logs the time it takes a function to execute'''
    #Decorator generator
    def decorator(func_to_decorate):
        def wrapper(*args, **kwargs):
            start = time.time()
            result = func_to_decorate(*args, **kwargs)
            elapsed = (time.time() - start)

            s = "[TIMING]:%s - %s" % (func_to_decorate.__name__,
                                                elapsed)
            open("log.txt", 'a').write(s)
            return result
        wrapper.__doc__ = func_to_decorate.__doc__
        wrapper.__name__ = func_to_decorate.__name__
        return wrapper
    return decorator
