from __future__ import unicode_literals, absolute_import, print_function

import datetime
import os
from functools import partial

from oauthlib.oauth2 import RequestValidator

__all__ = ['OAuth2RequestValidator']

__author__ = 'Fill Q'


class OAuth2RequestValidator(RequestValidator):
    def validate_user_match(self, id_token_hint, scopes, claims, request):
        return False

    def validate_silent_authorization(self, request):
        return False

    def get_id_token(self, token, token_handler, request):
        return False

    def validate_silent_login(self, request):
        return False

    def __init__(self, service, clientgetter, tokengetter, grantgetter,
                 usergetter=None, tokensetter=None, grantsetter=None):
        self._clientgetter = partial(clientgetter, service)
        self._tokengetter = partial(tokengetter, service)
        self._usergetter = partial(usergetter, service) if usergetter else usergetter
        self._tokensetter = partial(tokensetter, service) if tokensetter else tokensetter
        self._grantgetter = partial(grantgetter, service)
        self._grantsetter = partial(grantsetter, service) if grantsetter else grantsetter

    def _get_client_creds_from_request(self, request):
        if request.client_id is not None:
            return request.client_id, request.client_secret

        auth = request.headers.get('Authorization')
        if isinstance(auth, dict):
            return auth['username'], auth['password']

        return None, None

    def client_authentication_required(self, request, *args, **kwargs):
        def is_confidential(_client):
            if hasattr(_client, 'is_confidential'):
                return _client.is_confidential
            client_type = getattr(_client, 'client_type', None)
            if client_type:
                return client_type == 'confidential'
            return True

        grant_types = ('password', 'authorization_code', 'refresh_token')
        client_id, _ = self._get_client_creds_from_request(request)
        if client_id and request.grant_type in grant_types:
            client = self._clientgetter(client_id)
            if client:
                return is_confidential(client)
        return False

    def authenticate_client(self, request, *args, **kwargs):
        client_id, client_secret = self._get_client_creds_from_request(request)
        # log.debug('Authenticate client %r', client_id)

        client = self._clientgetter(client_id)
        if not client:
            # log.debug('Authenticate client failed, client not found.')
            return False

        request.client = client

        if hasattr(client, 'client_secret') and client.client_secret != client_secret:
            # log.debug('Authenticate client failed, secret not match.')
            return False

        # log.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        if client_id is None:
            client_id, _ = self._get_client_creds_from_request(request)

        # log.debug('Authenticate client %r.', client_id)
        client = request.client or self._clientgetter(client_id)
        if not client:
            # log.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        client = client or self._clientgetter(client_id)
        # log.debug('Confirm redirect uri for client %r and code %r.',
        #           client.client_id, code)
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            # log.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        # log.debug('Compare redirect uri for grant %r and %r.',
        #           grant.redirect_uri, redirect_uri)

        testing = 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ
        if testing and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # log.debug('Obtaining scope of refreshed token.')
        tok = self._tokengetter(refresh_token=refresh_token)
        return tok.scopes

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        if not scopes:
            # log.debug('Scope omitted for refresh token %r', refresh_token)
            return True
        # log.debug('Confirm scopes %r for refresh token %r',
        #           scopes, refresh_token)
        tok = self._tokengetter(refresh_token=refresh_token)
        return set(tok.scopes) == set(scopes)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        request.client = request.client or self._clientgetter(client_id)
        redirect_uri = request.client.default_redirect_uri
        # log.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        request.client = request.client or self._clientgetter(client_id)
        scopes = request.client.default_scopes
        # log.debug('Found default scopes %r', scopes)
        return scopes

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # log.debug('Destroy grant token for client %r, %r', client_id, code)
        grant = self._grantgetter(client_id=client_id, code=code)
        if grant:
            grant.delete()

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Persist the authorization code."""
        # log.debug(
        #     'Persist authorization code %r for client %r',
        #     code, client_id
        # )
        request.client = request.client or self._clientgetter(client_id)
        self._grantsetter(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        # log.debug('Save bearer token %r', token)
        self._tokensetter(token, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        # log.debug('Validate bearer token %r', token)
        tok = self._tokengetter(access_token=token)
        if not tok:
            msg = 'Bearer token not found.'
            request.error_message = msg
            # log.debug(msg)
            return False

        if tok.expires is not None and datetime.datetime.utcnow() > tok.expires:
            msg = 'Bearer token is expired.'
            request.error_message = msg
            # log.debug(msg)
            return False

        # validate scopes
        if scopes and not set(tok.scopes) & set(scopes):
            msg = 'Bearer token scope not valid.'
            request.error_message = msg
            # log.debug(msg)
            return False

        request.access_token = tok
        request.user = tok.user
        request.scopes = scopes

        if hasattr(tok, 'client'):
            request.client = tok.client
        elif hasattr(tok, 'client_id'):
            request.client = self._clientgetter(tok.client_id)
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        # log.debug('Validate client %r', client_id)
        client = request.client or self._clientgetter(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        client = client or self._clientgetter(client_id)
        # log.debug(
        #     'Validate code for client %r and code %r', client.client_id, code
        # )
        grant = self._grantgetter(client_id=client.client_id, code=code)
        if not grant:
            # log.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and datetime.datetime.utcnow() > grant.expires:
            # log.debug('Grant is expired.')
            return False

        request.state = kwargs.get('state')
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        if self._usergetter is None and grant_type == 'password':
            # log.debug('Password credential authorization is disabled.')
            return False

        default_grant_types = (
            'authorization_code', 'password',
            'client_credentials', 'refresh_token',
        )

        if hasattr(client, 'allowed_grant_types'):
            if grant_type not in client.allowed_grant_types:
                return False
        else:
            if grant_type not in default_grant_types:
                return False

        if grant_type == 'client_credentials':
            if not hasattr(client, 'user'):
                # log.debug('Client should have a user property')
                return False
            request.user = client.user

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        request.client = request.client or self._clientgetter(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        token = self._tokengetter(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        if response_type not in ('code', 'token'):
            return False

        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_user(self, username, password, client, request, *args, **kwargs):
        # log.debug('Validating username %r and its password', username)
        if self._usergetter is not None:
            user = self._usergetter(
                username, password, client, request, *args, **kwargs
            )
            if user:
                request.user = user
                return True
            return False
        # log.debug('Password credential authorization is disabled.')
        return False

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        if token_type_hint:
            tok = self._tokengetter(**{token_type_hint: token})
        else:
            tok = self._tokengetter(access_token=token)
            if not tok:
                tok = self._tokengetter(refresh_token=token)

        if tok:
            request.client_id = tok.client_id
            request.user = tok.user
            tok.delete()
            return True

        msg = 'Invalid token supplied.'
        # log.debug(msg)
        request.error_message = msg
        return False
