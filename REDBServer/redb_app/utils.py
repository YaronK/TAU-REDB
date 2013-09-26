"""
Utilities for all the other modules.
"""
import os
from ctypes import cdll
import time
import ctypes
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
import base64


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
    DLL_FILE_PATH = os.path.join(DLL_DIR_PATH, 'CliquerReduced')

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

    def get_maximum_clique(self, reorder=0):
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
        int_ptr = self.lib.get_max_clique_redb(self.g, opts)

        int_ptr = ctypes.cast(int_ptr, ctypes.POINTER(ctypes.c_int))

        try:
            clique_size = int_ptr[0]
        except:
            return []
        clique = [int_ptr[i] for i in range(1, 1 + clique_size)]

        self.lib.free_redb(int_ptr)
        self.lib.free_redb(opts)
        return clique

    def free(self):
        self.lib.graph_free(self.g)

    def edge_count(self):
        return self.lib.graph_edge_count(self.g)

    def __str__(self):
        return str(self.lib.graph_print(self.g))


##############################################################################
def view_or_basicauth(view, request, test_func, realm="", *args, **kwargs):
    """
    This is a helper function used by both 'logged_in_or_basicauth' and
    'has_perm_or_basicauth' that does the nitty of determining if they
    are already logged in or if they have provided proper http-authorization
    and returning the view if all goes well, otherwise responding with a 401.
    """
    if test_func(request.user):
        # Already logged in, just return the view.
        #
        return view(request, *args, **kwargs)

    # They are not logged in. See if they provided login credentials
    #
    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) == 2:
            # NOTE: We are only support basic authentication for now.
            #
            if auth[0].lower() == "basic":
                uname, passwd = base64.b64decode(auth[1]).split(':')
                user = authenticate(username=uname, password=passwd)
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        request.user = user
                        return view(request, *args, **kwargs)

    # Either they did not provide an authorization header or
    # something in the authorization attempt failed. Send a 401
    # back to them to ask them to authenticate.
    #
    response = HttpResponse()
    response.status_code = 401
    response['WWW-Authenticate'] = 'Basic realm="%s"' % realm
    return response


##############################################################################
def logged_in_or_basicauth(realm=""):
    """
    A simple decorator that requires a user to be logged in. If they are not
    logged in the request is examined for a 'authorization' header.

    If the header is present it is tested for basic authentication and
    the user is logged in with the provided credentials.

    If the header is not present a http 401 is sent back to the
    requestor to provide credentials.

    The purpose of this is that in several django projects I have needed
    several specific views that need to support basic authentication, yet the
    web site as a whole used django's provided authentication.

    The uses for this are for urls that are access programmatically such as
    by rss feed readers, yet the view requires a user to be logged in. Many rss
    readers support supplying the authentication credentials via http basic
    auth (and they do NOT support a redirect to a form where they post a
    username/password.)

    Use is simple:

    @logged_in_or_basicauth
    def your_view:
        ...

    You can provide the name of the realm to ask for authentication within.
    """
    def view_decorator(func):
        def wrapper(request, *args, **kwargs):
            return view_or_basicauth(func, request,
                                     lambda u: u.is_authenticated(),
                                     realm, *args, **kwargs)
        return wrapper
    return view_decorator


##############################################################################
def has_perm_or_basicauth(perm, realm=""):
    """
    This is similar to the above decorator 'logged_in_or_basicauth'
    except that it requires the logged in user to have a specific
    permission.

    Use:

    @logged_in_or_basicauth('asforums.view_forumcollection')
    def your_view:
        ...

    """
    def view_decorator(func):
        def wrapper(request, *args, **kwargs):
            return view_or_basicauth(func, request,
                                     lambda u: u.has_perm(perm),
                                     realm, *args, **kwargs)
        return wrapper
    return view_decorator


def log_timing():
    '''Decorator generator that logs the time it takes a function to execute'''
    # Decorator generator
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


def test_log(string):
    log_path = r"C:\Users\Yaron\Desktop\test_log.txt"
    log_row = time.asctime() + ": " + string + "\n"
    open(log_path, 'a').write(log_row)
