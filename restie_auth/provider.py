from functools import partial

from nameko.dependency_providers import Config
from nameko.rpc import ServiceProxy, ReplyListener
from restie.base import ServiceDependencyProvider

from .collector import AuthCollector
from .extensions import Authorization, Authentication
from .oauth2 import oauth2

__all__ = ['AuthManager']


class AuthManager(ServiceDependencyProvider):
    rpc_reply_listener = ReplyListener()
    collector = AuthCollector()

    authorization_required = lambda self, *args, **kwargs: partial(
        Authorization.decorator,
        collector=self.collector
    )(*args, **kwargs)

    login_required = lambda self, *args, **kwargs: partial(
        Authentication.decorator,
        collector=self.collector
    )(*args, **kwargs)

    login_validator = Authentication.login_validator_handler
    session_store = Authentication.session_store_handler

    def __init__(self, auth_service=None, oauth_validator=None):
        self.auth_service = auth_service
        self.oauth_validator = oauth_validator
        self.oauth2 = oauth2

    def setup(self):
        oauth2.oauth_validator = self.oauth_validator

    def get_dependency(self, worker_ctx):
        if self.auth_service:
            self.collector.proxy = ServiceProxy(worker_ctx, self.auth_service, self.rpc_reply_listener)

        oauth2.service = worker_ctx.service
        services = dict(
            authorization_required=self.authorization_required,
            login_required=self.login_required,
            oauth2=self.oauth2
        )
        return self.make_dependency(**services)


ConfigProvider = Config
