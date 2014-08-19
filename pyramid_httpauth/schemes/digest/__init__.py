from pyramid.httpexceptions import HTTPBadRequest
from pyramid_httpauth import wsgi_environ_cache
from pyramid_httpauth.schemes.digest import noncemanager
import logging
from .. import BaseScheme
from pyramid.response import Response
import pyramid.util
import binascii
import re
from . import utils


# Regular expression matching a single param in the HTTP_AUTHORIZATION header.
# This is basically <name>=<value> where <value> can be an unquoted token,
# an empty quoted string, or a quoted string where the ending quote is *not*
# preceded by a backslash.
_AUTH_PARAM_RE = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
_AUTH_PARAM_RE = re.compile(r"^\s*" + _AUTH_PARAM_RE + r"\s*$")


# Regular expression matching an unescaped quote character.
_UNESC_QUOTE_RE = r'(^")|([^\\]")'
_UNESC_QUOTE_RE = re.compile(_UNESC_QUOTE_RE)

# Regular expression matching a backslash-escaped characer.
_ESCAPED_CHAR = re.compile(r"\\.")

# WSGI environ key used to cache a validated digest response.
_ENVKEY_VALID_RESPONSE = "pyramid_httpauth.digest.valid_response"

# WSGI environ key used to indicate a stale nonce.
_ENVKEY_STALE_NONCE = "pyramid_httpauth.digest.stale_nonce"


class HttpDigestScheme(BaseScheme):

    def __init__(self, auth_policy, domain=None,
                 qop=None,
                 nonce_manager=None,
                 **kwargs):
        super(HttpDigestScheme, self).__init__(auth_policy, **kwargs)
        maybe_resolve = pyramid.util.DottedNameResolver(None).maybe_resolve
        nonce_manager = maybe_resolve(nonce_manager)
        if nonce_manager is None:
            nonce_manager = noncemanager.SignedNonceManager()
        elif callable(nonce_manager):
            nonce_manager = nonce_manager()

        self.domain = domain
        self.qop = qop
        self.nonce_manager = nonce_manager

    @wsgi_environ_cache('pyramid_httpauth.scheme.digest.auth_params')
    def _parse_authorization_token(self, request):
        scheme_name, param_str = \
            self.auth_policy.parse_authorization_header(request)
        params = {"scheme": scheme_name}
        if scheme_name is None or params is None: return None;

        kvpairs = []
        if param_str:
            for kvpair in param_str.split(","):
                if not kvpairs or _AUTH_PARAM_RE.match(kvpairs[-1]):
                    kvpairs.append(kvpair)
                else:
                    kvpairs[-1] = kvpairs[-1] + "," + kvpair
            if not _AUTH_PARAM_RE.match(kvpairs[-1]):
                logging.warning('Malformed auth parameters: %s' % param_str)
                return None

        for kvpair in kvpairs:
            (key, value) = kvpair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if _UNESC_QUOTE_RE.search(value):
                    logging.warning("Unescaped quote in quoted-string at "
                                    "Authorization header: %s" % value)
                    return None
                value = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], value)
            params[key] = value

        return params

    @wsgi_environ_cache('pyramid_httpauth.scheme.digest.parsed_params')
    def _get_authorization_params(self, request):
        params = self._parse_authorization_token(request)
        if params is None: return None;
        if params["scheme"].lower() != "digest":
            return None
        if not utils.validate_digest_parameters(params, self.realm):
            return None
        # Check that the digest is applied to the correct URI.
        if not utils.validate_digest_uri(params, request):
            return None
        # Check that the provided nonce is valid.
        # If this looks like a stale request, mark it in the request
        # so we can include that information in the challenge.
        if not utils.validate_digest_nonce(params, request, self.nonce_manager):
            request.environ[_ENVKEY_STALE_NONCE] = True
            return None
        return params

    @wsgi_environ_cache('pyramid_httpauth.scheme.digest.unauthenticated_userid')
    def unauthenticated_userid(self, request):
        params = self._get_authorization_params(request)
        if params is None: return None;
        try:
            return params['username']
        except KeyError:
            return None

    def _authenticate(self, request, params):
        """Authenticate digest-auth params against known passwords.

        This method checks the provided response digest to authenticate the
        request, using either the "get_password" or "get_pwdhash" callback
        to obtain the user's verifier.
        """
        username = params["username"]
        realm = params["realm"]
        response = params["response"]
        # Quick check if we've already validated these params.
        if request.environ.get(_ENVKEY_VALID_RESPONSE) == response:
            return True

        password = self.auth_policy.get_password(username)
        if password is None: return False;
        pwdhash = utils.calculate_pwdhash(username, password, realm)

        # Validate the digest response.
        if not utils.check_digest_response(params, request, pwdhash=pwdhash):
            return False
        # Cache the successful authentication.
        request.environ[_ENVKEY_VALID_RESPONSE] = response
        return True

    @wsgi_environ_cache('pyramid_httpauth.scheme.digest.authenticated_userid')
    def authenticated_userid(self, request):
        params = self._get_authorization_params(request)
        if params is None: return None;
        if not self._authenticate(request, params):
            return None
        return params['username']


    def _generate_opaque_from_realm(self, realm):
        crc = binascii.crc32(realm, 0x5aa53bb3) & 0xffffffff
        crc = hex(crc)
        if crc[0] == '-':
            crc = '-' + crc[3:]
        else:
            crc = crc[2:]
        return crc

    def _get_challenge_headers(self, request, check_stale=True):
        """Get headers necessary for a fresh digest-auth challenge.

        This method generates a new digest-auth challenge for the given
        request, including a fresh nonce.  If the environment is marked
        as having a stale nonce then this is indicated in the challenge.
        """
        params = {}
        params["realm"] = self.realm
        if self.domain is not None:
            params["domain"] = self.domain
        # Escape any special characters in those values, so we can send
        # them as quoted-strings.  The extra values added below are under
        # our control so we know they don't contain quotes.
        for key, value in params.items():
            params[key] = value.replace('"', '\\"')
        # Set various internal parameters.
        params["qop"] = self.qop
        params["nonce"] = self.nonce_manager.generate_nonce(request)
        params["algorithm"] = "MD5"
        # Mark the nonce as stale if told so by the environment.
        # NOTE:  The RFC says the server "should only set stale to TRUE if
        # it receives a request for which the nonce is invalid but with a
        # valid digest for that nonce".  But we can't necessarily check the
        # password at this stage, and it's only a "should", so don't bother.
        if check_stale and request.environ.get(_ENVKEY_STALE_NONCE):
            params["stale"] = "TRUE"
        # Construct the final header as quoted-string k/v pairs.
        value = ", ".join('%s="%s"' % itm for itm in params.items())
        return [("WWW-Authenticate", "Digest " + value)]

    def login_required(self, request):
        headers = self._get_challenge_headers(request)

        r = Response(status='401 Unauthorized',
                     headers=headers,
                     json_body={
                         'errors': {
                             'code': 401,
                             'message': 'You have to login to access this API',
                         }
                     })
        return r