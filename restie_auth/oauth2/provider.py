from __future__ import unicode_literals, absolute_import, print_function

from functools import partial
from inspect import isclass

from oauthlib.oauth2 import Server
from restie_auth.utils import extract_params, create_response, partialmethod
from werkzeug.utils import cached_property
from werkzeug.wrappers import Request

from .entrypoints import OAuth2AuthorizeHandler, OAuth2TokenHandler, OAuth2RevokeHandler
from .validator import OAuth2RequestValidator

__all__ = ['oauth2']


class OAuth2Provider(object):
    def __init__(self):
        self._token_expires_in = 3600  # config.get('OAUTH2_PROVIDER_TOKEN_EXPIRES_IN', 3600) @TODO add config here
        self._token_generator = None
        self._refresh_token_generator = None

    @property
    def oauth_validator(self):
        return getattr(self, '_oauth_validator', OAuth2RequestValidator)

    @oauth_validator.setter
    def oauth_validator(self, _validator):
        if isclass(_validator) and issubclass(_validator, OAuth2RequestValidator):
            setattr(self, '_oauth_validator', _validator)

    @property
    def service(self):
        return getattr(self, '_service', None)

    @service.setter
    def service(self, cls):
        setattr(self, '_service', cls)

    @cached_property
    def server(self):
        validator_key = '_validator'
        if hasattr(self, validator_key):
            return Server(
                getattr(self, validator_key),
                token_expires_in=self._token_expires_in,
                token_generator=self._token_generator,
                refresh_token_generator=self._refresh_token_generator,
            )

        if hasattr(self, '_clientgetter') and \
                hasattr(self, '_tokengetter') and \
                hasattr(self, '_tokensetter') and \
                hasattr(self, '_grantgetter') and \
                hasattr(self, '_grantsetter'):

            usergetter = None
            if hasattr(self, '_usergetter'):
                usergetter = self._usergetter

            validator = self.oauth_validator(
                service=self.service,
                clientgetter=getattr(self, '_clientgetter'),
                tokengetter=getattr(self, '_tokengetter'),
                grantgetter=getattr(self, '_grantgetter'),
                usergetter=usergetter,
                tokensetter=getattr(self, '_tokensetter'),
                grantsetter=getattr(self, '_grantsetter')
            )
            setattr(self, validator_key, validator)
            return Server(
                validator,
                token_expires_in=self._token_expires_in,
                token_generator=self._token_generator,
                refresh_token_generator=self._refresh_token_generator,
            )
        raise RuntimeError('application not bound to required getters')

    def _set_local_f(self, attr_name, f):
        if callable(f):
            setattr(self, attr_name, f)
        return f

    token_generator = partialmethod(_set_local_f, '_token_generator')
    refresh_token_generator = partialmethod(_set_local_f, '_refresh_token_generator')
    invalid_response = partialmethod(_set_local_f, '_invalid_response')
    clientgetter = partialmethod(_set_local_f, '_clientgetter')
    usergetter = partialmethod(_set_local_f, '_usergetter')
    tokengetter = partialmethod(_set_local_f, '_tokengetter')
    tokensetter = partialmethod(_set_local_f, '_tokensetter')
    grantgetter = partialmethod(_set_local_f, '_grantgetter')
    grantsetter = partialmethod(_set_local_f, '_grantsetter')

    authorize_handler = (lambda self, *args, **kwargs: partial(
        OAuth2AuthorizeHandler.decorator,
        provider=self
    )(*args, **kwargs))

    token_handler = (lambda self, *args, **kwargs: partial(
        OAuth2TokenHandler.decorator,
        provider=self
    )(*args, **kwargs))

    revoke_handler = (lambda self, *args, **kwargs: partial(
        OAuth2RevokeHandler.decorator,
        provider=self
    )(*args, **kwargs))

    def confirm_authorization_request(self, request):
        scope = request.values.get('scope') or ''
        scopes = scope.split()
        credentials = dict(
            client_id=request.values.get('client_id'),
            redirect_uri=request.values.get('redirect_uri', None),
            response_type=request.values.get('response_type', None),
            state=request.values.get('state', None)
        )
        # log.debug('Fetched credentials from request %r.', credentials)

        uri, http_method, body, headers = extract_params(request)

        ret = self.server.create_authorization_response(
            uri, http_method, body, headers, scopes, credentials
        )

        # log.debug('Authorization successful.')
        return create_response(*ret)

    def verify_request(self, scopes, request=None, uri=None, http_method=None, body=None, headers=None):
        if isinstance(request, Request):
            uri, http_method, body, headers = extract_params(request)
        return self.server.verify_request(
            uri, http_method, body, headers, scopes
        )

oauth2 = OAuth2Provider()
