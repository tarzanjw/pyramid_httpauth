Authentication Policy for Pyramid RESTful app
=============================================

Authentication policy for restful app. For more information please visit
https://github.com/tarzanjw/pyramid_restful_auth

Usage
---------------

To use this package, in the app function, just include it.

    config.include("pyramid_restful_auth")

In you *development.ini*

    restful_auth.dbsession = app.models.DBSession

Use *pyramid_restful_auth.models.RESTfulUser* to manage your users. Its table
name is *rest_user*
