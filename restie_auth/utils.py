from functools import partial

from six import iteritems, PY2
from restie.utils import json
from werkzeug.contrib.securecookie import SecureCookie
from werkzeug.contrib.sessions import generate_key
from werkzeug.security import gen_salt
from werkzeug.wrappers import Response

from restie.utils import CONSTANTS

get_constant = (lambda const, default=None: getattr(CONSTANTS, const, default))


def get_secret_key(default=None):
    if default is None:
        default = generate_key(gen_salt(20))
    return get_constant('SECRET_KEY', default=default)


def _get_uri_from_request(request):
    """
    The uri returned from request.uri is not properly urlencoded
    (sometimes it's partially urldecoded) This is a weird hack to get
    werkzeug to return the proper urlencoded string uri
    """
    uri = request.base_url
    if request.query_string:
        uri += '?' + request.query_string.decode('utf-8')
    return uri


def extract_params(request):
    """Extract request params."""

    uri = _get_uri_from_request(request)
    http_method = request.method
    headers = dict(request.headers)
    if 'wsgi.input' in headers:
        del headers['wsgi.input']
    if 'wsgi.errors' in headers:
        del headers['wsgi.errors']
    # Werkzeug, and subsequently Flask provide a safe Authorization header
    # parsing, so we just replace the Authorization header with the extraced
    # info if it was successfully parsed.
    if request.authorization:
        headers['Authorization'] = request.authorization

    body = request.form.to_dict()
    return uri, http_method, body, headers


def create_response(headers, body, status):
    response = Response(body or '')
    for k, v in iteritems(headers):
        response.headers[str(k)] = v

    response.status_code = status
    return response


class JSONSecureCookie(SecureCookie):
    serialization_method = json


if PY2:
    class partialmethod(partial):
        def __get__(self, instance, owner):
            if instance is None:
                return self
            return partial(self.func, instance,
                           *(self.args or ()), **(self.keywords or {}))
else:
    # noinspection PyUnresolvedReferences
    from functools import partialmethod
