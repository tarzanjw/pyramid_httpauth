__author__ = 'tarzan'

class BaseAdapter(object):
    def __init__(self, request, get_user_callback):
        self.request = request
        self.get_user_callback = get_user_callback

    def unauthenticated_userid(self):
        return None

    def authenticated_userid(self):
        return None
