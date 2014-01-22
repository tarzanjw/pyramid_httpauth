__author__ = 'tarzan'

from sqlalchemy import Column, types, Table, MetaData
from sqlalchemy.orm import mapper
from datetime import datetime

Base = None
DBSession = None

meta = MetaData()

def setup_database(session):
    global DBSession
    DBSession = session

_user_table = Table("rest_user", meta,
                    Column("id", types.Integer, primary_key=True,
                           autoincrement=True),
                    Column("username", types.VARCHAR(length=64),
                           unique=True, nullable=False),
                    Column("password", types.VARCHAR(length=64),
                           nullable=False),
                    Column("desc", types.TEXT),
                    Column("groups", types.TEXT),
                    Column("enabled", types.BOOLEAN,
                           default=True),
                    Column("last_modified_time", types.DateTime,
                           nullable=False,
                           default=datetime.now, onupdate=datetime.now)
                )

class RESTfulUser(object):
    def __init__(self, **kwargs):
        self.id = None
        self.username = None
        self.password = None
        self.desc = None
        self.groups = None
        self.enabled = None
        self.last_modified_time = None
        self.__dict__.update(kwargs)

    def __unicode__(self):
        return self.username

    def __str__(self):
        return self.__unicode__().encode('utf-8')

mapper(RESTfulUser, _user_table)

def get_rest_user(username):
    user = DBSession.query(RESTfulUser).filter(
        RESTfulUser.username == username,
        RESTfulUser.enabled).first()
    print user
    if user is not None:
        return {
            'id': user.id,
            'username': user.username,
            'password': user.password,
            'roles': user.groups,
        }
    return None
