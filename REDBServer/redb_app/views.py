"""
This module contains the server's Request, Submit and Compare handlers.
"""

# standard library imports
import json

# related third party imports
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

# local application/library specific imports
import actions
from redb_app.utils import logged_in_or_basicauth
from django.http.response import HttpResponseBadRequest

import logging
logger = logging.getLogger(__name__)


#==============================================================================
# Handlers
#==============================================================================
@csrf_exempt
@require_POST
@logged_in_or_basicauth()
def general_handler(request):
    try:
        query = actions.Query(request)
        query_type = query.check_validity()

        if query_type == "request":
            return request_handler(request)
        elif query_type == "submit":
            return submit_handler(request)
    except Exception as e:
        logger.error(str(e))
        return HttpResponseBadRequest()


def request_handler(request):
    """
    Handles a Request for descriptions.
    """
    request_action = actions.RequestAction(request)
    request_action.process_attributes()
    request_action.temp_function()
    request_action.db_filtering()
    # TODO: Commented out until fixed
    #request_action.dictionary_filtering()
    request_action.matching_grade_filtering()
    descriptions = request_action.get_descriptions()
    return HttpResponse(json.dumps(descriptions))


def submit_handler(request):
    """
    Handles a Submitted descriptions.
    """
    submit_action = actions.SubmitAction(request)
    if not submit_action.process_attributes():
        return HttpResponse(json.dumps("Unable to submit a Thunk"))
    submit_action.temp_function()
    submit_action.process_description()
    submit_action.insert_description()
    return HttpResponse(json.dumps("SUCCESS"))
