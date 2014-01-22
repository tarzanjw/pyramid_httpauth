__author__ = 'tarzan'

from . import BaseAdapter
import base64

class HttpBasicAdapter(BaseAdapter):

    def _parse_authorization_token(self):
        try:
            if not self.request.authorization:
                return None
            method, args = self.request.authorization
            _token = base64.b64decode(args)
            self._username, self._password = _token.split(':', 1)
        except (ValueError, TypeError, AttributeError), e:
            self._username = None
            self._password = None

    @property
    def username(self):
        try:
            return self._username
        except AttributeError:
            self._parse_authorization_token()
        return self._username

    @property
    def password(self):
        try:
            return self._password
        except AttributeError:
            self._parse_authorization_token()
        return self._password

    def unauthenticated_userid(self):
        return self.username

    def authenticated_userid(self):
        if not self.username:
            return None

        user = self.get_user_callback(self.username)
        if user['password'] == self.password:
            return self.username
        return None
