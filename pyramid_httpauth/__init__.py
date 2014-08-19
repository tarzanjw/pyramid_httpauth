__author__ = 'tarzan'


def wsgi_environ_cache(*names):
    """
    Wrap a function/method, cache its result for call with a request param into
    request.environ
    :param list[string] names: keys to cache into environ, the len(names) must
    be equal to the result's length or scalar
    :return:
    """
    def decorator(fn):
        def function_wrapper(self, request):
            scalar = len(names) == 1
            try:
                rs = [request.environ[cached_key] for cached_key in names]
            except KeyError:
                rs = fn(self, request)
                if scalar:
                    rs = [rs, ]
                request.environ.update(zip(names, rs))
            return rs[0] if scalar else rs
        return function_wrapper

    return decorator


from .http_auth_policy import HttpAuthPolicy


def includeme(config):
    """Include default httpauth settings into a pyramid config.

    This function provides a hook for pyramid to include the default settings
    for HTTP-Digest-Auth or HTTP-Basic-Auth.  Activate it like so:

        config.include("pyramid_httpauth")

    This will activate a HttpAuthenticationplicy instance with settings taken
    from the the application settings as follows:

        * httpauth.scheme:          default scheme to challenge client (digest
                                    or basic), default=digest
        * httpauth.realm:           realm string for auth challenge header
        * httpauth.qop:             qop string for auth challenge header
                                    (used for Digest Auth only)
        * httpauth.nonce_manager:   name of NonceManager class to use
                                    (used for Digest Auth only)
        * httpauth.domain:          domain string for auth challenge header
        * httpauth.get_password:    name of password-retrieval function
        * httpauth.groupfinder:     name of group-finder callback function

    It will also activate:

        * a forbidden view that will challenge for default scheme auth credentials.

    :type config: pyramid.config.Configurator
    """
    auth_policy = HttpAuthPolicy.create_from_settings(
        settings=config.get_settings())
    config.set_authentication_policy(auth_policy)
    config.add_forbidden_view(auth_policy.forbidden)