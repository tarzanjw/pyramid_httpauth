import six

__author__ = 'tarzan'

import unittest
from pyramid_httpauth import HttpAuthPolicy
from pyramid_httpauth.schemes.digest import HttpDigestScheme
import wsgiref.util
from pyramid_httpauth.schemes.digest import utils
import os
from . import make_request
from .test_http_auth_policy import EasyNonceManager


def get_challenge(scheme, request):
    """Get a new digest-auth challenge from the policy."""
    res = scheme.login_required(request)
    www_authenticate = res.headers.get('www-authenticate')
    req = make_request(HTTP_AUTHORIZATION=www_authenticate)
    return scheme._parse_authorization_token(req)


def set_authz_header(request, params):
    """Set Authorization header to match the given params."""
    authz = ",".join('%s="%s"' % v for v in params.items())
    request.environ["HTTP_AUTHORIZATION"] = "Digest " + authz


def build_response(params, request, username, password, **kwds):
    """Build a response to the digest-auth challenge."""
    def random_cnonce():
        cn = os.urandom(8)
        if six.PY3:
            import binascii
            return binascii.hexlify(cn).decode('utf-8')
        else:
            return cn.encode('hex')
    params = params.copy()
    # remove qop from the challenge parameters.
    params.pop("qop", None)
    params.update(kwds)
    params.setdefault("username", username)
    params.setdefault("uri", wsgiref.util.request_uri(request.environ))
    # do qop=auth unless specified otherwise in kwds
    params.setdefault("qop", "auth")
    if not params["qop"]:
        del params["qop"]
    else:
        params.setdefault("cnonce", random_cnonce())
        params.setdefault("nc", "0000001")
    resp = utils.calculate_digest_response(params, request, password=password)
    params["response"] = resp
    set_authz_header(request, params)
    return params


class TestHttpDigestScheme(unittest.TestCase):

    def test_without_authorization_header(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        self.assertIsNone(scheme.unauthenticated_userid(request))
        self.assertIsNone(scheme.authenticated_userid(request))

    def test_with_wrong_authorization_header(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request(HTTP_AUTHORIZATION='Digest ha ha ha')
        self.assertIsNone(scheme.unauthenticated_userid(request))
        self.assertIsNone(scheme.authenticated_userid(request))

        request = make_request(HTTP_AUTHORIZATION='Digest realm=Sync')
        self.assertIsNone(scheme.unauthenticated_userid(request))
        self.assertIsNone(scheme.authenticated_userid(request))

    def test_with_incorrect_password(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testingxxx')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        self.assertEqual(scheme.unauthenticated_userid(request), 'tester')
        self.assertNotEqual(scheme.authenticated_userid(request), 'tester')

    def test_with_correct_password(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        self.assertEqual(scheme.unauthenticated_userid(request), 'tester')
        self.assertEqual(scheme.authenticated_userid(request), 'tester')

    def test_login_required(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        res = scheme.login_required(request)
        self.assertEqual(res.status_code, 401)
        www_authenticate = res.headers.get('www-authenticate')
        www_authenticate = www_authenticate.lower()
        self.assertTrue(www_authenticate.startswith('digest'))

    def test_identify_with_mismatched_uri(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request(PATH_INFO="/path_one")
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        self.assertNotEqual(scheme.unauthenticated_userid(request), None)
        request = make_request(PATH_INFO="/path_one")
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        request.PATH_INFO = '/path_two'
        self.assertEquals(scheme.unauthenticated_userid(request), None)

    def test_identify_with_bad_noncecount(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/one")
        # Do an initial auth to get the nonce.
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing", nc="01")
        self.assertNotEquals(scheme.unauthenticated_userid(request), None)

        # Authing without increasing nc will fail.
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="01")
        self.assertEquals(scheme.unauthenticated_userid(request), None)

        # Authing with a badly-formed nc will fail
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02XXX")
        self.assertEquals(scheme.unauthenticated_userid(request), None)

        # Authing with increasing nc will succeed.
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02")
        self.assertEquals(scheme.unauthenticated_userid(request), 'tester')
        self.assertEquals(scheme.authenticated_userid(request), 'tester')

    def test_rfc2617_example(self):
        password = "Circle Of Life"
        params = {"username": "Mufasa",
                  "realm": "testrealm@host.com",
                  "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                  "uri": "/dir/index.html",
                  "qop": "auth",
                  "nc": "00000001",
                  "cnonce": "0a4f113b",
                  "opaque": "5ccc069c403ebaf9f0171e9517f40e41"}
        http_auth_policy = HttpAuthPolicy("testrealm@host.com", 'digest',
                                          get_password=lambda usr: 'Circle Of Life')
        scheme = HttpDigestScheme(http_auth_policy,
                                  nonce_manager=EasyNonceManager())
        # Calculate the response according to the RFC example parameters.
        request = make_request(REQUEST_METHOD="GET",
                               PATH_INFO="/dir/index.html")
        resp = utils.calculate_digest_response(params, request, password=password)
        # Check that it's as expected from the RFC example section.
        self.assertEquals(resp, "6629fae49393a05397450978507c4ef1")
        # Check that we can auth using it.
        params["response"] = resp
        set_authz_header(request, params)
        self.assertEquals(scheme.unauthenticated_userid(request), "Mufasa")
        self.assertEquals(scheme.authenticated_userid(request), "Mufasa")

    def test_auth_good_get_with_vars(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/hi?who=me")
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        self.assertEquals(scheme.authenticated_userid(request), 'tester')

    def test_auth_good_legacy_mode(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/legacy")
        params = get_challenge(scheme, request)
        params = build_response(params, request, "tester", "testing", qop=None)
        self.failIf("qop" in params)
        self.assertTrue(scheme._authenticate(request, params))

    def test_auth_good_authint_mode(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/authint",
                               HTTP_CONTENT_MD5="1B2M2Y8AsgTpgAmY7PhCfg==")
        params = get_challenge(scheme, request)
        params = build_response(params, request, "tester", "testing",
                                qop="auth-int")
        self.assertTrue(scheme._authenticate(request, params))

    def test_auth_with_different_realm(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        params["realm"] = "other-realm"
        build_response(params, request, "tester", "testing")
        self.assertEquals(scheme.unauthenticated_userid(request), None)
        self.assertEquals(scheme.authenticated_userid(request), None)

    def test_auth_with_no_password_callbacks(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        self.assertEquals(scheme.authenticated_userid(request), None)

    def test_auth_with_bad_digest_response(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        params = build_response(params, request, "tester", "testing")
        authz = request.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(params["response"], "WRONG")
        request.environ["HTTP_AUTHORIZATION"] = authz
        params["response"] += "WRONG"
        self.assertEquals(scheme.authenticated_userid(request), None)
        
    def test_auth_with_unknown_qop(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        params = build_response(params, request, "tester", "testing")
        params["qop"] = "super-duper"
        self.assertRaises(ValueError, scheme._authenticate, request, params)

    def test_auth_with_failed_password_lookup(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: None)
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        self.assertEquals(scheme.unauthenticated_userid(request), "tester")
        self.assertEquals(scheme.authenticated_userid(request), None)

    def test_auth_with_missing_nonce(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request()
        params = get_challenge(scheme, request)
        build_response(params, request, "tester", "testing")
        authz = request.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("nonce", " notanonce")
        request.environ["HTTP_AUTHORIZATION"] = authz
        self.assertEquals(scheme.unauthenticated_userid(request), None)
        self.assertEquals(scheme.authenticated_userid(request), None)

    def test_auth_with_invalid_content_md5(self):
        http_auth_policy = HttpAuthPolicy('TestHttpDigestScheme', 'digest',
                                          get_password=lambda usr: 'testing')
        scheme = HttpDigestScheme(http_auth_policy)
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/authint",
                               HTTP_CONTENT_MD5="1B2M2Y8AsgTpgAmY7PhCfg==")
        params = get_challenge(scheme, request)
        params = build_response(params, request, "tester", "testing",
                                qop="auth-int")
        request.environ["HTTP_CONTENT_MD5"] = "8baNZjN6gc+g0gdhccuiqA=="
        self.assertEquals(scheme._authenticate(request, params), False)


class TestDigestAuthHelpers(unittest.TestCase):
    """Testcases for the various digest-auth helper functions."""

    def test_validate_digest_parameters_qop(self):
        params = dict(scheme="Digest", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456", qop="auth",
                      uri="/my/page", cnonce="98765")
        # Missing "nc"
        self.failIf(utils.validate_digest_parameters(params))
        params["nc"] = "0001"
        self.failUnless(utils.validate_digest_parameters(params))
        # Wrong realm
        self.failIf(utils.validate_digest_parameters(params, realm="otherrealm"))
        self.failUnless(utils.validate_digest_parameters(params, realm="testrealm"))
        # Unknown qop
        params["qop"] = "super-duper"
        self.failIf(utils.validate_digest_parameters(params))
        params["qop"] = "auth-int"
        self.failUnless(utils.validate_digest_parameters(params))
        params["qop"] = "auth"
        # Unknown algorithm
        params["algorithm"] = "sha1"
        self.failIf(utils.validate_digest_parameters(params))
        params["algorithm"] = "md5"
        self.failUnless(utils.validate_digest_parameters(params))

    def test_validate_digest_parameters_legacy(self):
        params = dict(scheme="Digest", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456")
        # Missing "uri"
        self.failIf(utils.validate_digest_parameters(params))
        params["uri"] = "/my/page"
        self.failUnless(utils.validate_digest_parameters(params))
        # Wrong realm
        self.failIf(utils.validate_digest_parameters(params, realm="otherrealm"))
        self.failUnless(utils.validate_digest_parameters(params, realm="testrealm"))

    def test_validate_digest_uri(self):
        request = make_request(SCRIPT_NAME="/my", PATH_INFO="/page")
        """:type : pyramid.testing.DummyRequest"""
        params = dict(scheme="Digest", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456", qop="auth",
                      uri="/my/page", cnonce="98765", nc="0001")
        self.failUnless(utils.validate_digest_uri(params, request))
        # Using full URI still works
        params["uri"] = "http://localhost/my/page"
        self.failUnless(utils.validate_digest_uri(params, request))
        # Check that query-string is taken into account.
        params["uri"] = "http://localhost/my/page?test=one"
        self.failIf(utils.validate_digest_uri(params, request))
        request.environ["QUERY_STRING"] = "test=one"
        self.failUnless(utils.validate_digest_uri(params, request))
        params["uri"] = "/my/page?test=one"
        self.failUnless(utils.validate_digest_uri(params, request))
        # Check that only MSIE is allow to fudge on the query-string.
        params["uri"] = "/my/page"
        request.environ["HTTP_USER_AGENT"] = "I AM FIREFOX I HAVE TO DO IT PROPERLY"
        self.failIf(utils.validate_digest_uri(params, request))
        request.environ["HTTP_USER_AGENT"] = "I AM ANCIENT MSIE PLZ HELP KTHXBYE"
        self.failUnless(utils.validate_digest_uri(params, request))
        self.failIf(utils.validate_digest_uri(params, request, msie_hack=False))
        params["uri"] = "/wrong/page"
        self.failIf(utils.validate_digest_uri(params, request))
