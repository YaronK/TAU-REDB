"""
This module contains the server's Request, Submit and Compare handlers.
"""

# standard library imports
import json

# related third party imports
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

# local application/library specific imports
import redb_server_actions


#==============================================================================
# Handlers
#==============================================================================
@csrf_exempt
def general_handler(http_post):
    data = json.loads(http_post['action'])
    check_validity(data)
    action_type = data['type']

    if(action_type == 'request'):
        return request_handler(data['attributes'])
    elif(action_type == 'submit'):
        return submit_handler(data['attributes'], data['description'])


def check_validity(data):
    # TODO
    pass


def request_handler(attributes):
    """
    Handles a Request for descriptions.
    """
    print "REDB: request_handler called"

    request_action = redb_server_actions.RequestAction(attributes)
    request_action.check_validity()
    request_action.generate_temp_function()
    request_action.filter_functions()
    descriptions = request_action.get_descriptions()

    http_response = HttpResponse(json.dumps(descriptions))
    print "REDB: request_handler finished"
    return http_response


def submit_handler(attributes, description):
    """
    Handles a Submitted descriptions.
    """
    print "REDB: submit_handler called"
    submit_action = redb_server_actions.SubmitAction(attributes, description)
    submit_action.check_validity()
    submit_action.generate_temp_function()
    submit_action.generate_description()
    submit_action.insert_description()

    print "DEBUG: submit_handler finished"
    return HttpResponse("Success")
