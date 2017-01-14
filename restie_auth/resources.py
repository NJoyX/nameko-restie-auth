from nameko.events import EventDispatcher, event_handler, BROADCAST
from nameko.rpc import rpc
from restie import http, codes

from .provider import AuthManager, ConfigProvider
from .utils import get_secret_key

REGISTER_SCOPES = 'roles:register'


class AuthResource(object):
    name = 'authz'

    scopes = set()
    auth = AuthManager()
    dispatch = EventDispatcher()
    config = ConfigProvider()

    @rpc
    def get_secret_key(self):
        return self.config.get('secret_key', get_secret_key())

    @rpc
    def verify_request(self, uri, http_method, body, headers, scopes):
        valid, req = self.auth.oauth2.verify_request(
            uri=uri,
            http_method=http_method,
            body=body,
            headers=headers,
            scopes=scopes
        )
        return valid

    @rpc
    def register_scopes(self, scopes):
        self.dispatch(REGISTER_SCOPES, scopes)
        return True

    @event_handler(name, REGISTER_SCOPES, handler_type=BROADCAST, reliable_delivery=False)
    def handle_new_scopes(self, scopes):
        if isinstance(scopes, (list, tuple, set)):
            self.scopes.update(scopes)

    @http(['GET', 'POST'], '/oauth/authorize')
    @auth.login_required
    @auth.oauth2.authorize_handler
    def oauth2_authorize(self, request, *args, **kwargs):
        return self.authorize(request, *args, **kwargs)

    @http('GET', '/oauth/token')
    @auth.oauth2.token_handler
    def oauth2_access_token(self, request):
        return self.access_token(request)

    @http(['POST'], '/oauth/revoke')
    @auth.oauth2.revoke_handler
    def revoke_token(self, request):
        pass

    @http(['GET'], '/oauth/errors')
    def oauth_errors(self, request):
        return codes.BAD_REQUEST, request.args.get('error_description')

    def authorize(self, request, *args, **kwargs):
        raise NotImplementedError('Must implement')

    def access_token(self, request):
        pass

    def load_client(self, client_id):
        raise NotImplementedError('Must implement load_client')

    oauth_clientgetter = auth.oauth2.clientgetter(lambda self, *args, **kwargs: self.load_client(*args, **kwargs))

    def load_grant(self, client_id, code):
        raise NotImplementedError('Must implement load_grant')

    oauth_grantgetter = auth.oauth2.grantgetter(lambda self, *args, **kwargs: self.load_grant(*args, **kwargs))

    def save_grant(self, client_id, code, request, *args, **kwargs):
        raise NotImplementedError('Must implement save_grant')

    oauth_grantsetter = auth.oauth2.grantsetter(lambda self, *args, **kwargs: self.save_grant(*args, **kwargs))

    def load_token(self, access_token=None, refresh_token=None):
        raise NotImplementedError('Must implement load_token')

    oauth_tokengetter = auth.oauth2.tokengetter(lambda self, *args, **kwargs: self.load_token(*args, **kwargs))

    def save_token(self, token, request, *args, **kwargs):
        raise NotImplementedError('Must implement save_token')

    oauth_tokensetter = auth.oauth2.tokensetter(lambda self, *args, **kwargs: self.save_token(*args, **kwargs))

    def get_user(self, username, password, *args, **kwargs):
        raise NotImplementedError('Must implement get_user')

    oauth_usergetter = auth.oauth2.usergetter(lambda self, *args, **kwargs: self.get_user(*args, **kwargs))
