"""
This module contains the server's Request, Submit and Compare handlers.
"""

# standard library imports
import json

# related third party imports
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

# local application/library specific imports
import actions
from utils import log


#==============================================================================
# Handlers
#==============================================================================
@csrf_exempt
def general_handler(http_post):
    try:
        query = actions.Query(http_post)
        query.check_validity()
        query.process()
        query.authenticate_user()
        if query.type == 'request':
            return request_handler(query.data)
        elif query.type == 'submit':
            return submit_handler(query.data, query.username)
    except:
        return HttpResponse("ERROR")


@log
def request_handler(data):
    """
    Handles a Request for descriptions.
    """
    request_action = actions.RequestAction(data)
    request_action.check_validity()
    request_action.process_attributes()
    request_action.temp_function()
    request_action.db_filtering()
    request_action.dictionaries_filtering()
    request_action.matching_grade_filtering()
    descriptions = request_action.get_descriptions()
    return HttpResponse(json.dumps(descriptions))


@log
def submit_handler(data, username):
    """
    Handles a Submitted descriptions.
    """
    submit_action = actions.SubmitAction(data, username)
    submit_action.check_validity()
    submit_action.process_attributes()
    submit_action.temp_function()
    submit_action.process_description()
    submit_action.insert_description()
    return HttpResponse("SUCCESS")
