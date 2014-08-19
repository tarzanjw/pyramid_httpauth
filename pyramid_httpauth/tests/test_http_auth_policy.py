import unittest
from pyramid.config import Configurator
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import Everyone, Allow, Deny, Authenticated
from webtest import TestApp
from pyramid_httpauth import HttpAuthPolicy


_USERS = {
    'aa': ('aapwd', ['a',]),
    'bb': ('bbpwd', ['b',]),
}

def sampleapp_get_password(username):
    try:
        return _USERS[username][0]
    except KeyError:
        return None

def sampleapp_groupfinder(username):
    try:
        return _USERS[username][1]
    except KeyError:
        return None

APP_SETTINGS = {
    'httpauth.realm': 'SampleApp',
    'httpauth.get_password': __name__ + ':sampleapp_get_password',
    'httpauth.groupfinder':  __name__ + ':sampleapp_groupfinder',
}


def sample_app(app_settings={}):
    def everyone_view(request):
        return 'everyone'

    def authenticated_view(request):
        return 'authenticated'

    def aa_view(requeset):
        return 'aa'

    def no_permission(request):
        return 'no-permission'

    class Root(object):
        __acl__ = [
            (Allow, Everyone, 'guest'),
            (Allow, Authenticated, 'auth'),
            (Allow, 'aa', 'aa'),
        ]
        def __init__(self, request):
            self.request = request

    settings = APP_SETTINGS.copy()
    settings.update(app_settings)
    config = Configurator(
        settings=settings,
        root_factory=Root,
        authorization_policy=ACLAuthorizationPolicy()
    )
    config.include('pyramid_httpauth')

    config.add_view(no_permission,
                    name='no-perm',
                    context=Root,
                    renderer='string')

    config.add_view(everyone_view,
                    name='guest',
                    context=Root,
                    renderer='string',
                    permission='guest')

    config.add_view(authenticated_view,
                    name='auth',
                    context=Root,
                    renderer='string',
                    permission='auth')

    config.add_view(aa_view,
                    name='aa',
                    context=Root,
                    renderer='string',
                    permission='aa')

    app = config.make_wsgi_app()
    return TestApp(app)

def sample_basic_app(settings={}):
    settings.update({'httpauth.scheme': 'basic'})
    return sample_app(settings)


class EasyNonceManager(object):
    """NonceManager that thinks everything is valid."""

    def generate_nonce(self, request):
        return "aaa"

    def is_valid_nonce(self, nonce, request):
        return True

    def get_next_nonce(self, nonce, request):
        return nonce + "a"

    def get_nonce_count(self, nonce):
        return None

    def set_nonce_count(self, nonce, nc):
        return None


class TestHttpAuthPolicy(unittest.TestCase):
    def test_from_settings(self):
        def ref(class_name):
            return __name__ + ":" + class_name
        policy = HttpAuthPolicy.create_from_settings(
            realm="test",
            nonce_manager=ref("EasyNonceManager"),
            domain="http://example.com",
            get_password=ref("sampleapp_get_password"),
        )
        scheme = policy._get_scheme('digest')
        self.assertEquals(scheme.realm, "test")
        self.assertEquals(scheme.domain, "http://example.com")
        self.failUnless(isinstance(scheme.nonce_manager, EasyNonceManager))
        self.failUnless(policy.get_password is sampleapp_get_password)

    def _test_401(self, app):
        """
        :type app: TestApp
        :return:
        """
        res = app.get('/no-perm')
        """:type : webtest.TestResponse"""

        res = app.get('/guest')
        res = app.get('/auth', status=401)
        res = app.get('/aa', status=401)

        # to lazy to add test that submit authorization header here

    def test_basic_401(self):
        self._test_401(sample_basic_app())

    def test_digest_401(self):
        self._test_401(sample_app())