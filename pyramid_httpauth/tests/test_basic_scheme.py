__author__ = 'tarzan'

import unittest
from pyramid_httpauth import HttpAuthPolicy
from pyramid_httpauth.schemes.basic import HttpBasicScheme
from . import make_request


class TestHttpBasicScheme(unittest.TestCase):
    def test_without_authorization_header(self):
        http_auth_policy = HttpAuthPolicy('TestHttpBasicScheme', 'basic')
        scheme = HttpBasicScheme(http_auth_policy)
        request = make_request()
        self.assertIsNone(scheme.unauthenticated_userid(request))
        self.assertIsNone(scheme.authenticated_userid(request))

    def test_with_wrong_authorization_header(self):
        http_auth_policy = HttpAuthPolicy('TestHttpBasicScheme', 'basic')
        scheme = HttpBasicScheme(http_auth_policy)
        request = make_request(HTTP_AUTHORIZATION='Basic ha ha ha')
        self.assertIsNone(scheme.unauthenticated_userid(request))
        self.assertIsNone(scheme.authenticated_userid(request))

    def test_with_incorrect_password(self):
        http_auth_policy = HttpAuthPolicy('TestHttpBasicScheme', 'basic',
                                          get_password=lambda usr: usr + 'xx')
        scheme = HttpBasicScheme(http_auth_policy)
        request = make_request(HTTP_AUTHORIZATION='Basic dXNyOnB3ZA==') # usr:pwd
        self.assertEqual(scheme.unauthenticated_userid(request), 'usr')
        self.assertIsNone(scheme.authenticated_userid(request))


    def test_with_correct_password(self):
        http_auth_policy = HttpAuthPolicy('TestHttpBasicScheme', 'basic',
                                          get_password=lambda usr: 'pwd')
        scheme = HttpBasicScheme(http_auth_policy)
        request = make_request(HTTP_AUTHORIZATION='Basic dXNyOnB3ZA==') # usr:pwd
        self.assertEqual(scheme.unauthenticated_userid(request), 'usr')
        self.assertEqual(scheme.authenticated_userid(request), 'usr')
