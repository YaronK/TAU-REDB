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
def general_handler(request):
    try:
        query = actions.Query(request)
        query.check_validity()
        query_type, query_data = query.process()

        if not request.user.is_authenticated():
            raise("Unknown user.")

        if query_type == 'request':
            return request_handler(query_data)
        elif query_type == 'submit':
            return submit_handler(query_data, request.user)

    except Exception as e:
        print e
        return HttpResponse("ERROR")


@log
def request_handler(query_data):
    """
    Handles a Request for descriptions.
    """
    request_action = actions.RequestAction(query_data)
    request_action.check_validity()
    request_action.process_attributes()
    request_action.temp_function()
    request_action.db_filtering()
    request_action.dictionaries_filtering()
    request_action.matching_grade_filtering()
    descriptions = request_action.get_descriptions()
    return HttpResponse(json.dumps(descriptions))


@log
def submit_handler(query_data, user):
    """
    Handles a Submitted descriptions.
    """
    submit_action = actions.SubmitAction(query_data, user)
    submit_action.check_validity()
    submit_action.process_attributes()
    submit_action.temp_function()
    submit_action.process_description()
    submit_action.insert_description()
    return HttpResponse("SUCCESS")
