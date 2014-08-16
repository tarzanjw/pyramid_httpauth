pyramid_httpauth
================

This is an authentication policy for __pyramid__ that verifies credentials
using either HTTP-Digest-Auth or HTTP-Basic-Auth protocol.

With a reference to https://github.com/mozilla-services/pyramid_digestauth/

Usage
-----

To use this package, in the app function, just include it.

    config.include("pyramid_httpauth")

In you *development.ini*

    * httpauth.schema:          default schema to challenge client (digest
                                or basic), default=digest
    * httpauth.realm:           realm string for auth challenge header
    * httpauth.qop:             qop string for auth challenge header
                                (used for Digest Auth only)
    * httpauth.nonce_manager:   name of NonceManager class to use
                                (used for Digest Auth only)
    * httpauth.domain:          domain string for auth challenge header
    * httpauth.get_password:    name of password-retrieval function
    * httpauth.get_pwdhash:     name of pwdhash-retrieval function
    * httpauth.groupfinder:     name of group-finder callback function
