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
from utils import log, _decode_dict


#==============================================================================
# Handlers
#==============================================================================
@csrf_exempt
@log
def general_handler(http_post):
    data = json.loads(http_post.FILES['action'].read(),
                      object_hook=_decode_dict)
    check_validity(data)
    action_type = data['type']

    if(action_type == 'request'):
        return request_handler(data['attributes'])
    elif(action_type == 'submit'):
        return submit_handler(data['attributes'], data['description_data'])


@log
def check_validity(data):
    # TODO
    pass


@log
def request_handler(attributes):
    """
    Handles a Request for descriptions.
    """
    try:
        request_action = actions.RequestAction(attributes)
        request_action.check_validity()
        request_action.process_attributes()
        request_action.temp_function()
        request_action.db_filtering()
        request_action.dictionaries_filtering()
        request_action.matching_grade_filtering()
        descriptions = request_action.get_descriptions()
        return HttpResponse(json.dumps(descriptions))
    except:
        return HttpResponse("ERROR")


@log
def submit_handler(attributes, description_data):
    """
    Handles a Submitted descriptions.
    """
    try:
        submit_action = actions.SubmitAction(attributes, description_data)
        submit_action.check_validity()
        submit_action.process_attributes()
        submit_action.temp_function()
        submit_action.insert_description()
        return HttpResponse("SUCCESS")
    except:
        return HttpResponse("ERROR")
