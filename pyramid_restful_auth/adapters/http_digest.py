__author__ = 'tarzan'

from . import BaseAdapter
import base64
import hashlib
from pyramid.response import Response
import unicodedata
import binascii
import time
import struct

class HttpDigestAdapter(BaseAdapter):

    def _parse_authorization_token(self):
        try:
            if not self.request.authorization:
                return {}
            method, args = self.request.authorization
            if method.lower() != 'digest':
                return {}
            return args
        except (ValueError, TypeError, AttributeError), e:
            return {}

    @property
    def challenge(self):
        try:
            return self._challenge
        except AttributeError:
            self._challenge = self._parse_authorization_token()
        return self._challenge

    @property
    def username(self):
        return self.challenge.get('username', None)

    def unauthenticated_userid(self):
        return self.username

    def _kd_md5(self, msg):
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        return hashlib.md5(msg).hexdigest()

    def _kd_sha1(self, msg):
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        return hashlib.sha1(msg).hexdigest()

    def authenticated_userid(self):
        if not self.username:
            return None

        user = self.get_user_callback(self.username)
        password = user['password']
        chals = self.challenge
        realm = chals['realm']
        nonce = chals['nonce']
        qop = chals.get('qop', None)
        uri = chals['uri']
        algorithm = chals.get('algorithm', 'md5').upper()
        opaque = chals.get('opaque')

        if opaque != self._generate_opaque_from_realm(realm):
            return None

        if algorithm == 'MD5':
            hash_func = self._kd_md5
        elif algorithm == 'SHA':
            hash_func = self._kd_sha1
        else:
            assert False, "Algorithm %s has not been implemented" % algorithm

        ha1 = hash_func("%s:%s:%s" % (self.username, realm, password))
        ha2 = hash_func("%s:%s" % (self.request.method.upper(), uri))

        if qop is None:
            response = hash_func("%s:%s:%s" % (ha1, nonce, ha2))
        elif 'auth' in qop.split(','):
            response = hash_func("%s:%s:%s:%s:%s:%s" % (
                ha1,
                nonce,
                chals['nc'],
                chals['cnonce'],
                qop,
                ha2
            ))

        if response != chals['response']:
            return None

        return self.username

    def _generate_realm(self, request):
        return 'API: ' + \
               unicodedata.normalize(
                   'NFKD',
                   unicode(request.path)).encode('ascii','ignore')

    def _generate_nonce(self, request):
        return base64.b64encode(struct.pack('>d', time.time()))

    def _generate_opaque_from_realm(self, realm):
        crc = binascii.crc32(realm, 0x5aa53bb3) & 0xffffffff
        crc = hex(crc)
        if crc[0] == '-':
            crc = '-' + crc[3:]
        else:
            crc = crc[2:]
        return crc

    def login_required(self, request):
        r = Response()
        r.status_code = 401
        r.content_type = 'application/json'
        r.body = '{"errors":{"code":401,"message":"You have to login to access this API"}}'

        realm = self._generate_realm(request)
        r.www_authenticate = ('Digest', {
            'realm': realm,
            'qop': 'auth',
            'algorithm': 'MD5',
            'nonce': self._generate_nonce(request),
            'opaque': self._generate_opaque_from_realm(realm),
        })

        return r