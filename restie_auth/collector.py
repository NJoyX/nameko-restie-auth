from restie.helpers import DecoratorCollector

PROXY_KEY = '_proxy'


class AuthCollector(DecoratorCollector):
    @property
    def proxy(self):
        return getattr(self, PROXY_KEY, None)

    @proxy.setter
    def proxy(self, p):
        if self.proxy is None:
            setattr(self, PROXY_KEY, p)
