__author__ = 'tarzan'

import re
from pyramid.response import Response
import unicodedata
import time
import binascii
from pyramid.security import Authenticated, Everyone

class BaseAdapter(object):
    def __init__(self, request, get_user_callback):
        self.request = request
        self.get_user_callback = get_user_callback

    def unauthenticated_userid(self):
        return None

    def authenticated_userid(self):
        return None

from http_basic import HttpBasicAdapter
from http_digest import HttpDigestAdapter

class AuthPolicy(object):
    """
    An authentication proxy for HTTP Header Auth (Basic, Digest  ...).

    This auto performs by parsing the header (request.authorization) then
    use a callback to fetch User information, after that it will do the
    authentication corresponding to fetched user

    User information:
    user = {
        "password": "the plain password"
        "roles": "the roles that are concatenated by ; or ,"
    }

    Callback function:
    def get_user(id):
        # id maybe username (It is, for Http Basic and Http Digest)
        pass
    """

    adapters = {
        'dummy': BaseAdapter,
        'basic': HttpBasicAdapter,
        'digest': HttpDigestAdapter,
    }

    def __init__(self, get_user_callback):
        self.get_user_callback = get_user_callback

    def _create_adapter(self, name, request):
        return self.adapters[name](request, self.get_user_callback_wrapper)

    def _get_adapter(self, request):
        """
        Get adapter to process authentication based on request
        """
        try:
            return request.__rest_auth_adapter__
        except AttributeError:
            try:
                method, args = request.authorization
                adapter_name = method.lower()
            except (ValueError, AttributeError, TypeError):
                adapter_name = 'dummy'
            request.__rest_auth_adapter__ = \
                self._create_adapter(adapter_name, request)
        return request.__rest_auth_adapter__

    def get_user_callback_wrapper(self, user_id):
        if user_id is None:
            return None
        else:
            _u = self.get_user_callback(user_id)
            if not isinstance(_u, dict):
                u = {
                    'username': None,
                    'password': None,
                    'roles': '',
                }
                for k in u:
                    try:
                        u[k] = getattr(_u, k)
                    except AttributeError:
                        pass
            else:
                u = _u
        if not u['roles']:
            u['roles'] = ''
        return u

    def _get_current_user(self, request):
        """
        Get User info for current request

        :return User info
        """
        try:
            return request.__rest_auth_current_user__
        except AttributeError:
            user_id = self.unauthenticated_userid(request)
            request.__rest_auth_current_user__ = \
                self.get_user_callback_wrapper(user_id)
        return request.__rest_auth_current_user__

    def unauthenticated_userid(self, request):
        return self._get_adapter(request).unauthenticated_userid()

    def authenticated_userid(self, request):
        return self._get_adapter(request).authenticated_userid()

    def effective_principals(self, request):
        user_id = self.authenticated_userid(request)
        if user_id is None:
            return []
        user = self._get_current_user(request)
        roles = [Everyone, Authenticated] + re.split(r'[;,]', user['roles'])
        return roles

    def remember(self, request, principal, **kw):
        return ()

    def forget(self, request):
        return ()

    def login_required(self, request):
        adapter = self._get_adapter(request)
        if not hasattr(adapter, 'login_required'):
            adapter = self._create_adapter('digest', request)
        return adapter.login_required(request)

    def forbidden(self, request):
        if not self.authenticated_userid(request):
            return self.login_required(request)

        r = Response()
        r.status_code = 403
        r.content_type = 'application/json'
        r.body = '{"errors":{"code":403,"message":"You are not authorized to access this API"}}'
        return r

    def _fetch_user_from_request(self, request):
        return None

    def get_user(self, request):
        try:
            return request.__rest_user__
        except AttributeError:
            request.__rest_user__ = self._fetch_user_from_request(request)
        return request.__rest_user__