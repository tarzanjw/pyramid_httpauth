__author__ = 'tarzan'

from auth_policy import AuthPolicy
import importlib

def includeme(config):
    """
    :type config: pyramid.config.Configurator
    """
    from models import get_rest_user, setup_database
    dbsession_path = config.registry.settings["restful_auth.dbsession"]
    module_name, attr_name = dbsession_path.rsplit('.', 1)
    module = importlib.import_module(module_name, package=None)
    dbsession = getattr(module, attr_name)
    setup_database(dbsession)

    auth = AuthPolicy(get_user_callback=get_rest_user)
    config.set_authentication_policy(auth)
    config.add_forbidden_view(auth.forbidden)