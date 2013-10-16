__author__ = 'tarzan'

import time
import os
import hashlib
import re
import unittest
from pyramid import testing
from pyramid.config import Configurator
from pyramid.security import Everyone, Authenticated
from . import AuthPolicy
from webtest import TestApp
from webob.descriptors import parse_auth
import logging

logging.basicConfig(level=logging.INFO)

def sample_app(app_settings={}, get_user_callback=None):
    def home_view(request):
        return 'he he'

    auth_policy = AuthPolicy(get_user_callback)
    settings = {
        'a':'b',
    }
    settings.update(app_settings)
    config = Configurator(
        settings=settings,
        authentication_policy=auth_policy,
    )
    config.add_forbidden_view(auth_policy.forbidden)

    config.add_route('home', '/')

    config.add_view(home_view,
                    route_name='home',
                    renderer='string',
                    permission='view')

    app = config.make_wsgi_app()
    return TestApp(app)

class AuthPolicyTest(unittest.TestCase):
    def setUp(self):
        super(AuthPolicyTest, self).setUp()
        self.auth_policy = AuthPolicy(self.get_user_function)
        self.app = sample_app({}, self.get_user_function)

    def _create_request(self):
        return testing.DummyRequest(
            path='/path/to/api',
            params={
                'arg1': 'arg1 value',
                'arg2': 'arg2 value',
            },
        )

    def get_user_function(self, user_id):
        _users = {
            'gaia': {
                'password': 'lion',
                'roles': 'gaia,titan'
            },
            'Mufasa': {
                'password': 'Circle Of Life',
                'roles': 'vice-lionking',
            }
        }
        try:
            return _users[user_id]
        except KeyError:
            return None

    def test_dummy(self):
        request = self._create_request()
        ap = self.auth_policy

        self.assertIsNone(ap.unauthenticated_userid(request))
        self.assertIsNone(ap.authenticated_userid(request))
        self.assertListEqual(ap.effective_principals(request), [])

    def test_basic(self):
        ap = self.auth_policy

        # test with exist user, correct password
        request = self._create_request()
        request.authorization = ('Basic', 'Z2FpYTpsaW9u') # gaia:lion
        self.assertEqual(ap.unauthenticated_userid(request), 'gaia')
        self.assertEqual(ap.authenticated_userid(request), 'gaia')
        self.assertSetEqual(
            set(ap.effective_principals(request)),
            set(('titan', 'gaia', Everyone, Authenticated))
        )

        # test with exist user, incorrect password
        request = self._create_request()
        request.authorization = ('Basic', 'Z2FpYTpsaW9uMQ==') # gaia:lion1
        self.assertEqual(ap.unauthenticated_userid(request), 'gaia')
        self.assertIsNone(ap.authenticated_userid(request))
        self.assertListEqual(ap.effective_principals(request), [])

        # test with non-exist user
        request = self._create_request()
        request.authorization = ('Basic', 'emV1czpwaGFudG9t') # zeus:phantom
        self.assertEqual(ap.unauthenticated_userid(request), 'zeus')
        self.assertIsNone(ap.authenticated_userid(request))
        self.assertListEqual(ap.effective_principals(request), [])

    def test_digest(self):
        # From mitsuhiko/werkzeug (used with permission).
        def unquote_header_value(value, is_filename=False):
            r"""Unquotes a header value.  (Reversal of :func:`quote_header_value`).
            This does not use the real unquoting but what browsers are actually
            using for quoting.

            :param value: the header value to unquote.
            """
            if value and value[0] == value[-1] == '"':
                # this is not the real unquoting, but fixing this so that the
                # RFC is met will result in bugs with internet explorer and
                # probably some other browsers as well.  IE for example is
                # uploading files with "C:\foo\bar.txt" as filename
                value = value[1:-1]

                # if this is a filename and the starting characters look like
                # a UNC path, then just return the value without quotes.  Using the
                # replace sequence below on a UNC path has the effect of turning
                # the leading double slash into a single slash and then
                # _fix_ie_filename() doesn't work correctly.  See #458.
                if not is_filename or value[:2] != '\\\\':
                    return value.replace('\\\\', '\\').replace('\\"', '"')
            return value

        # From mitsuhiko/werkzeug (used with permission).
        def parse_dict_header(value):
            """Parse lists of key, value pairs as described by RFC 2068 Section 2 and
            convert them into a python dict:

            >>> d = parse_dict_header('foo="is a fish", bar="as well"')
            >>> type(d) is dict
            True
            >>> sorted(d.items())
            [('bar', 'as well'), ('foo', 'is a fish')]

            If there is no value for a key it will be `None`:

            >>> parse_dict_header('key_without_value')
            {'key_without_value': None}

            To create a header from the :class:`dict` again, use the
            :func:`dump_header` function.

            :param value: a string with a dict header.
            :return: :class:`dict`
            """
            from urllib2 import parse_http_list as _parse_list_header
            result = {}
            for item in _parse_list_header(value):
                if '=' not in item:
                    result[item] = None
                    continue
                name, value = item.split('=', 1)
                if value[:1] == value[-1:] == '"':
                    value = unquote_header_value(value[1:-1])
                result[name] = value
            return result        # test unauthorized

        def build_digest_header(method, url, chals, username, password):
            from urlparse import urlparse

            realm = chals['realm']
            nonce = chals['nonce']
            qop = chals.get('qop')
            algorithm = chals.get('algorithm')
            opaque = chals.get('opaque')

            if algorithm is None:
                _algorithm = 'MD5'
            else:
                _algorithm = algorithm.upper()
            # lambdas assume digest modules are imported at the top level
            if _algorithm == 'MD5':
                def md5_utf8(x):
                    if isinstance(x, str):
                        x = x.encode('utf-8')
                    return hashlib.md5(x).hexdigest()
                hash_utf8 = md5_utf8
            elif _algorithm == 'SHA':
                def sha_utf8(x):
                    if isinstance(x, str):
                        x = x.encode('utf-8')
                    return hashlib.sha1(x).hexdigest()
                hash_utf8 = sha_utf8
            # XXX MD5-sess
            KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

            if hash_utf8 is None:
                return None

            # XXX not implemented yet
            entdig = None
            p_parsed = urlparse(url)
            path = p_parsed.path
            if p_parsed.query:
                path += '?' + p_parsed.query

            A1 = '%s:%s:%s' % (username, realm, password)
            A2 = '%s:%s' % (method, path)

            if qop is None:
                respdig = KD(hash_utf8(A1), "%s:%s" % (nonce, hash_utf8(A2)))
            elif qop == 'auth' or 'auth' in qop.split(','):
                import random
                nonce_count = random.randint(1, 1000)
                ncvalue = '%08x' % nonce_count
                s = str(nonce_count).encode('utf-8')
                s += nonce.encode('utf-8')
                s += time.ctime().encode('utf-8')
                s += os.urandom(8)

                cnonce = (hashlib.sha1(s).hexdigest()[:16])
                noncebit = "%s:%s:%s:%s:%s" % (nonce, ncvalue, cnonce, qop, hash_utf8(A2))
                respdig = KD(hash_utf8(A1), noncebit)
            else:
                # XXX handle auth-int.
                return None

            # XXX should the partial digests be encoded too?
            base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
                   'response="%s"' % (username, realm, nonce, path, respdig)
            if opaque:
                base += ', opaque="%s"' % opaque
            if algorithm:
                base += ', algorithm="%s"' % algorithm
            if entdig:
                base += ', digest="%s"' % entdig
            if qop:
                base += ', qop=auth, nc=%s, cnonce="%s"' % (ncvalue, cnonce)

            return 'Digest %s' % (base)

        # test unauthorized
        request = self._create_request()
        ap = self.auth_policy
        self.assertIsNone(ap.unauthenticated_userid(request))
        self.assertIsNone(ap.authenticated_userid(request))
        self.assertSetEqual(
            set(ap.effective_principals(request)),
            set([]))


        # test incorrect password
        r = ap.login_required(request)
        self.assertEqual(r.status_int, 401)
        self.assertIn('www-authenticate', r.headers)
        www_authenticate = r.headers['www-authenticate']
        print www_authenticate
        method, s_chals = re.split(r'\s+', www_authenticate, 1)
        self.assertEqual(method.lower(), 'digest')
        chals = parse_dict_header(s_chals)
        authorization = build_digest_header('GET', '/', chals, 'gaia', 'lion1')
        request = self._create_request()
        request.authorization = parse_auth(authorization)
        ap = self.auth_policy
        self.assertEqual(ap.unauthenticated_userid(request), 'gaia')
        self.assertIsNone(ap.authenticated_userid(request))
        self.assertSetEqual(
            set(ap.effective_principals(request)),
            set([]))

        ## test correct password
        r = ap.login_required(request)
        self.assertEqual(r.status_int, 401)
        self.assertIn('www-authenticate', r.headers)
        www_authenticate = r.headers['www-authenticate']
        method, s_chals = re.split(r'\s+', www_authenticate, 1)
        self.assertEqual(method.lower(), 'digest')
        chals = parse_dict_header(s_chals)
        authorization = build_digest_header('GET', '/', chals, 'gaia', 'lion')
        request = self._create_request()
        request.authorization = parse_auth(authorization)
        ap = self.auth_policy
        self.assertEqual(ap.unauthenticated_userid(request), 'gaia')
        self.assertEqual(ap.authenticated_userid(request), 'gaia')
        self.assertSetEqual(
            set(ap.effective_principals(request)),
            set(['gaia','titan', Everyone, Authenticated]))
