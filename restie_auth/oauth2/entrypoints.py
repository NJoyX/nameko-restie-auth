from __future__ import unicode_literals, print_function, absolute_import

from collections import namedtuple

from oauthlib import oauth2
from oauthlib.common import add_params_to_uri
from six import text_type
from restie_auth.utils import extract_params, create_response
from restie.helpers import DecoratorEntrypoint
from werkzeug.utils import redirect, cached_property

from .collector import OAuth2EntrypointsCollector

__all__ = ['OAuth2AuthorizeHandler', 'OAuth2TokenHandler', 'OAuth2RevokeHandler']


class OAuth2BaseEntrypoint(DecoratorEntrypoint):
    collector = OAuth2EntrypointsCollector()
    provider = None
    redirect_uri = None

    def __init__(self, provider):
        self.provider = provider

    @cached_property
    def error_uri(self):
        _default = '/oauth/errors'
        _error_uri = self.container.config.get('OAUTH2_PROVIDER_ERROR_URI', _default)
        if _error_uri:
            return _error_uri
        return _default

    def setup(self):
        self.collector.register_provider(self)

    def stop(self):
        self.collector.unregister_provider(self)
        super(OAuth2BaseEntrypoint, self).stop()


class OAuth2BaseExceptionEntrypoint(OAuth2BaseEntrypoint):
    def process_exception(self, request, exc, *args, **kwargs):
        if isinstance(exc, oauth2.FatalClientError):
            return redirect(exc.in_uri(self.error_uri))
        elif isinstance(exc, oauth2.OAuth2Error):
            return redirect(exc.in_uri(self.redirect_uri or self.error_uri))
        elif isinstance(exc, oauth2.AccessDeniedError):
            return redirect(exc.in_uri(self.redirect_uri))
        return redirect(add_params_to_uri(
            self.error_uri, {'error': text_type(exc)}
        ))


class OAuth2AuthorizeHandler(OAuth2BaseExceptionEntrypoint):
    def process_request(self, request, *args, **kwargs):
        server = self.provider.server
        uri, http_method, body, headers = extract_params(request)

        self.redirect_uri = request.values.get('redirect_uri', self.error_uri)
        _oauth2 = namedtuple('oauth2', '')()

        if request.method in ('GET', 'HEAD'):
            # log.debug('Found redirect_uri %s.', redirect_uri)

            ret = server.validate_authorization_request(
                uri, http_method, body, headers
            )
            scopes, credentials = ret
            _oauth2 = namedtuple('oauth2', ['scopes'] + credentials.keys())(scopes, **credentials.values())

        request.oauth2 = _oauth2
        return request

    def process_response(self, response, request, *args, **kwargs):
        if not isinstance(response, bool):
            # if is a response or redirect
            return response

        if not response:
            # denied by user
            e = oauth2.AccessDeniedError()
            return redirect(e.in_uri(self.redirect_uri))

        return self.provider.confirm_authorization_request(request)


class OAuth2TokenHandler(OAuth2BaseEntrypoint):
    def process_response(self, response, request, *args, **kwargs):
        uri, http_method, body, headers = extract_params(request)
        # log.debug('Fetched extra credentials, %r.', credentials)
        ret = self.provider.server.create_token_response(
            uri, http_method, body, headers, response
        )
        return create_response(*ret)


class OAuth2RevokeHandler(OAuth2BaseEntrypoint):
    def process_response(self, response, request, *args, **kwargs):
        token = request.values.get('token')
        request.token_type_hint = request.values.get('token_type_hint')
        if token:
            request.token = token

        uri, http_method, body, headers = extract_params(request)
        ret = self.provider.server.create_revocation_response(
            uri, headers=headers, body=body, http_method=http_method
        )
        return create_response(*ret)
