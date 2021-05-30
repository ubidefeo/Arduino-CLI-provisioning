# helper functions
from datetime import datetime
from time import sleep
import requests
from requests.models import Response


def send_request(request_obj, print_request=False, print_response=False):
    prepared_req = request_obj.prepare()
    if(print_request):
        pretty_print_POST(prepared_req)
    session = requests.Session()
    response = session.send(prepared_req)
    if(print_response):
        print("*" * 100)
        print(f"Response Code: {response.status_code}")
        print(f"Response: {response}")
    return response


def pretty_print_POST(req):
    print('{}{}{}{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))


def get_time_string():
    return f'{datetime.now()}'.replace(" ", "_").replace(":", ".")
