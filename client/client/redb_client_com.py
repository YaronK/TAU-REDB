"""
Methods and utilities required for communicating with the server.
"""

# related third party imports
import json
from redb_client_utils import _decode_dict


#==============================================================================
# Taken from http://code.activestate.com
#==============================================================================
import httplib
import mimetypes
import mimetools


def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to
    be uploaded as files. Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()  # @UnusedVariable
    return_data = h.file.read()
    return return_data


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files. Returns (content_type, body) ready for httplib.HTTP
    instance.
    """
    BOUNDARY = mimetools.choose_boundary()
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % \
                  (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


#==============================================================================
# Submit/Request Functions
#==============================================================================
def send_request(request, host):
    """
    Given a jsoned Request instance, sends it. Returns a Response instance.
    """
    response = None

    try:
        response = Response()
        response.from_json(post_multipart(host,
                                         "/redb/",
                                         [],
                                         [("action",
                                           "action",
                                           request)]
                                         ))
    except:
        print "REDB: An error occurred while requesting descriptions!"
        response = None

    return response


def send_submit(submit, host):
    """
    Given a jsoned Submit instance, sends it.
    """
    retval = post_multipart(host,
                            "/redb/",
                            [],
                            [("action",
                              "action",
                              submit)]
                            )
    # handle response
    if retval:
        print "REDB: Uploaded description to server successfully."
    else:
        print "REDB: An error occurred while submitting descriptions!"


class Response:
    """
    A response from the server to a request.
    """
    def __init__(self, \
                  suggested_descriptions_list=None):

        self.suggested_descriptions = suggested_descriptions_list

    def to_json(self):
        return json.dumps(self.suggested_descriptions)

    def from_json(self, json_obj):
        self.suggested_descriptions = json.loads(json_obj,
                                                 object_hook=_decode_dict)
