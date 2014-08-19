from pyramid.response import Response
from pyramid_httpauth import wsgi_environ_cache

__author__ = 'tarzan'

from . import BaseScheme
import base64
import six

# WSGI environ key used to cache parsed http basic scheme username and password.
_ENVKEY_PARSED_BASIC_SCHEME_USERNAME = "pyramid_httpauth.scheme.basic.username"
_ENVKEY_PARSED_BASIC_SCHEME_PASSWORD = "pyramid_httpauth.scheme.basic.password"


class HttpBasicScheme(BaseScheme):

    @wsgi_environ_cache(_ENVKEY_PARSED_BASIC_SCHEME_USERNAME,
                        _ENVKEY_PARSED_BASIC_SCHEME_PASSWORD)
    def _parse_authorization_token(self, request):
        params = self.get_authorization_parrams(request)
        if params is None:
            username, password = None, None
        else:
            try:
                _token = base64.b64decode(params)
                if six.PY3:
                    _token = _token.decode('utf-8')
                username, password = _token.split(':', 1)
                if six.PY2:
                    password = password.decode('utf-8')
            except (ValueError, TypeError):
                username, password = None, None
        return username, password

    def get_username(self, request):
        username, password = self._parse_authorization_token(request)
        return username

    def get_password(self, request):
        username, password = self._parse_authorization_token(request)
        return password

    def unauthenticated_userid(self, request):
        return self.get_username(request)

    def authenticated_userid(self, request):
        username = self.unauthenticated_userid(request)
        pwd_from_request = self.get_password(request)
        password = self.auth_policy.get_password(username)
        if password == pwd_from_request:
            return username
        return None

    def login_required(self, request):
        www_authenticate = 'Basic realm=%s' \
                           % self.auth_policy.realm.replace('"', '\\"')
        r = Response(status='401 Unauthorized',
                     headers={
                         'www-authenticate': www_authenticate,
                     },
                     json_body={
                         'errors': {
                             'code': 401,
                             'message': 'You have to login to access this API',
                         }
                     })
        return r
