__author__ = 'tarzan'

class BaseScheme(object):
    def __init__(self, auth_policy, **kwargs):
        """
        :param pyramid_httpauth.http_auth_policy.HttpAuthPolicy auth_policy: the
        http authentication policy instance that create this scheme
        :return:
        """
        self.auth_policy = auth_policy

    def get_authorization_parrams(self, request):
        scheme_name, params = \
            self.auth_policy._parse_authorization_header(request)
        print (scheme_name, params)
        return params

    def unauthenticated_userid(self, request):
        raise NotImplementedError()

    def authenticated_userid(self, request):
        raise NotImplementedError()

    def login_required(self, request):
        raise NotImplementedError()