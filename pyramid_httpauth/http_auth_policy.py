__author__ = 'tarzan'

import pyramid.util
from pyramid.response import Response
from pyramid.security import Authenticated, Everyone
from pyramid.httpexceptions import HTTPBadRequest
from pyramid_httpauth import schemes, wsgi_environ_cache
import logging

# WSGI environ key used to cache parsed scheme name and params.
_ENVKEY_PARSED_SCHEME_NAME = "pyramid_httpauth.parsed_scheme_name"
_ENVKEY_PARSED_SCHEME_PARAMS = "pyramid_httpauth.parsed_scheme_params"

# WSGI environ key used to cache parsed scheme instance
_ENVKEY_PARSED_SCHEME = "pyramid_httpauth.parsed_scheme"


def _default_get_pwd_callback(username):
    logging.warning('`httpauth.get_password` has not been implemented yet.')
    return None

def _default_group_finder_callback(username):
    logging.warning('`httpauth.groupfinder` has not been implemented yet.')
    return None


class HttpAuthPolicy(object):
    """
    An authentication proxy for HTTP Header Auth (Basic, Digest  ...).

    This performs by parsing the header (request.authorization) then use
    use the schema to fetch information corresponding to schema class.
    """

    _scheme_classes = {
        None: schemes.NoneScheme,
        'basic': schemes.HttpBasicScheme,
        'digest': schemes.HttpDigestScheme,
    }

    def __init__(self, realm, challenge_scheme_name='digest', get_password=None, groupfinder=None, **kwargs):
        maybe_resolve = pyramid.util.DottedNameResolver(None).maybe_resolve
        get_password = maybe_resolve(get_password)
        groupfinder = maybe_resolve(groupfinder)
        assert challenge_scheme_name is not None
        if get_password is None:
            get_password = _default_get_pwd_callback
        else:
            assert callable(get_password)
        if groupfinder is None:
            groupfinder = _default_group_finder_callback
        else:
            assert callable(groupfinder)

        self.realm = realm
        self.challenge_scheme_name = challenge_scheme_name
        self.get_password = get_password
        self.groupfinder = groupfinder

        self._kwargs = kwargs
        self._scheme_instances = {}

    @classmethod
    def create_from_settings(cls, settings=None, prefix='httpauth.', **kwargs):
        if settings is not None:
            data = {k[len(prefix):]: v
                    for k, v in settings.items() if k.startswith(prefix)}
        else:
            data = {}
        data.update(kwargs)
        realm = data.pop('realm', None)
        assert realm, 'You have to configure a not empty string at ' \
                      '%srealm to use pyramid_httpauth' % prefix
        data['challenge_scheme_name'] = data.pop('scheme', 'digest')
        return cls(realm, **data)

    def _get_scheme(self, name):
        """
        Create a scheme instance due to its name
        :rtype : schemes.BaseScheme
        """
        if name:
            name = name.lower()
        try:
            return self._scheme_instances[name]
        except KeyError:
            try:
                cls = self._scheme_classes[name]
            except KeyError:
                logging.warning('HTTP authentication scheme "%s" is '
                                'not supported', name)
                raise HTTPBadRequest('HTTP authentication scheme "%s" is '
                                     'not supported' % name)
            scheme = cls(self, **self._kwargs)
            self._scheme_instances[name] = scheme
            return scheme

    @wsgi_environ_cache(_ENVKEY_PARSED_SCHEME_NAME,
                        _ENVKEY_PARSED_SCHEME_PARAMS)
    def parse_authorization_header(self, request):
        """
        Get scheme name due to a request
        :param pyramid.request.Request request: request to get scheme name
        :rtype : (string, string)
        """
        authz = request.environ.get("HTTP_AUTHORIZATION")
        if authz is None:
            scheme_name = None
            params_str = None
        else:
            scheme_name, params_str = authz.split(None, 1)
            request.environ[_ENVKEY_PARSED_SCHEME_NAME] = scheme_name
            request.environ[_ENVKEY_PARSED_SCHEME_PARAMS] = params_str
        return (scheme_name, params_str)

    @wsgi_environ_cache(_ENVKEY_PARSED_SCHEME)
    def _get_scheme_for_request(self, request):
        """
        Get scheme for current a request
        :param pyramid.request.Request request: request to get scheme
        :rtype : schemes.BaseScheme
        """
        scheme_name, scheme_params = \
            self.parse_authorization_header(request)
        scheme = self._get_scheme(scheme_name)
        request.environ[_ENVKEY_PARSED_SCHEME] = scheme
        return scheme

    @wsgi_environ_cache('httpauth.unauthenticated_userid')
    def unauthenticated_userid(self, request):
        """Get the username for this request without authentication"""
        return self._get_scheme_for_request(request).\
            unauthenticated_userid(request)

    @wsgi_environ_cache('httpauth.authenticated_userid')
    def authenticated_userid(self, request):
        """Get the authenticated username for this request"""
        return self._get_scheme_for_request(request).\
            authenticated_userid(request)

    @wsgi_environ_cache('httpauth.effective_principals')
    def effective_principals(self, request):
        """Get the list of principals for this request"""
        username = self.authenticated_userid(request)
        principals = [Everyone, ]
        if username is None:
            return principals
        principals.append(username)
        groups = self.groupfinder(username)
        if groups is not None:
            principals.extend(groups)

        return principals

    def remember(self, request, principal, **kw):
        """Just do not do anything because I think HTTP Auth does not need
        to remember"""
        return ()

    def forget(self, request):
        """Due to not remember, not forget to"""
        return ()

    def login_required(self, request):
        scheme = self._get_scheme(self.challenge_scheme_name)
        return scheme.login_required(request)

    def forbidden(self, request):
        if not self.authenticated_userid(request):
            return self.login_required(request)

        r = Response(status='404 Fobidden', json_body={
            'errors': {
                'code': 403,
                'messages': 'You are not authorized to access this API',
            }
        })
        return r