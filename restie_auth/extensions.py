from inspect import isclass

from nameko import exceptions as nameko_exceptions
from nameko.exceptions import safe_for_serialization
from restie_auth.utils import extract_params, create_response
from restie.helpers import DecoratorEntrypoint
from restie.utils import response_triple
from werkzeug.contrib.sessions import FilesystemSessionStore, SessionStore
from werkzeug.http import dump_cookie
from werkzeug.utils import cached_property
from werkzeug.wrappers import Response

from .exceptions import Forbidden
from .utils import get_secret_key, JSONSecureCookie

SESSION_STORE_VAR = '_sess_store'


class AuthProvider(DecoratorEntrypoint):
    def __init__(self, collector):
        self.collector = collector

    @property
    def authz(self):
        return self.collector.proxy

    def setup(self):
        self.collector.register_provider(self)

    def stop(self):
        self.collector.unregister_provider(self)
        super(AuthProvider, self).stop()


class Authorization(AuthProvider):
    def __init__(self, collector, roles):
        super(Authorization, self).__init__(collector)
        assert isinstance(roles, (tuple, list)), "Authentication roles must be tuple or list"
        self.roles = roles

    def process_request(self, request, *args, **kwargs):
        try:
            self.authz.register_scopes.call_async(scopes=self.roles)
        except nameko_exceptions.UnknownService:
            pass

        uri, http_method, body, headers = extract_params(request)
        try:
            valid = self.authz.verify_request(
                uri=uri,
                http_method=http_method,
                body=body,
                headers=headers,
                scopes=self.roles
            )
            if valid:
                return request
        except nameko_exceptions.UnknownService:
            pass

        raise Forbidden('Unauthorised access')


class Authentication(AuthProvider):
    login_validator = lambda self, *args, **kwargs: False

    def __init__(self, collector, ignore_errors=False):
        super(Authentication, self).__init__(collector)
        self.ignore_errors = ignore_errors

    @cached_property
    def config(self):
        return self.container.config

    @cached_property
    def secret_key(self):
        try:
            secret_key = self.authz.get_secret_key()
        except nameko_exceptions.UnknownService:
            secret_key = get_secret_key()
        return secret_key

    @cached_property
    def cookie_key(self):
        return self.config.get('SESSION_COOKIE_NAME', 'session_id')

    @classmethod
    def login_validator_handler(cls, f):
        if callable(f):
            cls.login_validator = f
        return f

    @classmethod
    def session_store_handler(cls, f):
        if callable(f):
            setattr(cls, SESSION_STORE_VAR, f)
        return f

    @cached_property
    def session_store(self):
        store = getattr(self, SESSION_STORE_VAR, None)
        if isclass(store):
            store = store()

        if isinstance(store, SessionStore):
            return store
        return FilesystemSessionStore()

    def get_session(self, request):
        _cookie = JSONSecureCookie.load_cookie(request=request, key=self.cookie_key, secret_key=self.secret_key)
        sid = _cookie.get('sid')
        if sid is None:
            return self.session_store.new()
        else:
            return self.session_store.get(sid)

    def process_request(self, request, *args, **kwargs):
        session = self.get_session(request=request)

        valid = self.login_validator(request, *args, **kwargs)

        if not valid:
            raise Forbidden('Unauthorised access')
        request.session = session
        return request

    def process_response(self, response, request, *args, **kwargs):
        if request.session.should_save:
            self.session_store.save(request.session)
            _securecookie = JSONSecureCookie(dict(sid=request.session.sid), self.secret_key)
            max_age = self.config.get('SESSION_COOKIE_AGE', 1209600)
            path = self.config.get('SESSION_COOKIE_PATH', '/')
            secure = bool(self.config.get('SESSION_COOKIE_SECURE', '0'))
            domain = self.config.get('SESSION_COOKIE_DOMAIN', None)

            if not isinstance(response, Response):
                status, headers, payload = response_triple(response)
                if headers is None:
                    headers = {}
                headers['Set-Cookie'] = dump_cookie(
                    key=self.cookie_key,
                    value=_securecookie.serialize(),
                    max_age=max_age,
                    path=path,
                    domain=domain,
                    secure=secure,
                    httponly=True
                )
                return status, headers, payload

            _securecookie.save_cookie(
                response, self.cookie_key,
                max_age=max_age, path=path, domain=domain, secure=secure, httponly=True, force=True
            )
        return response

    def process_exception(self, request, exc, *args, **kwargs):
        if self.ignore_errors:
            return

        if isinstance(exc, Forbidden):
            return create_response({}, safe_for_serialization(exc), exc.status_code)
