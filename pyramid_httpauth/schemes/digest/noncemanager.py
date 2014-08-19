# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Cornice (Sagrada)
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (ryan@rfk.id.au)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""

Nonce-management classes for pyramid_digestauth.

"""

import os
import time
import hmac
import base64
import heapq
import threading
from hashlib import md5
import six
from . import utils

if six.PY3:
    xrange = range
    str_encode = lambda s: s.encode('utf-8')
else:
    str_encode = lambda s: s


class NonceManager(object):
    """Interface definition for management of digest-auth nonces.

    This class defines the necessary methods for managing nonces as
    part of the digest-auth protocol:

        * generate_nonce:    create a new unique nonce
        * is_valid_nonce:    check for validity of a nonce
        * get_next_nonce:    get next nonce to be used by client
        * set_nonce_count:   record nonce counter sent by client
        * get_nonce_count:   retrieve nonce counter sent by client

    Nonce management is split out into a separate class to make it easy
    to adjust the various time-vs-memory-security tradeoffs involved -
    for example, you might provide a custom NonceManager that stores its
    state in memcache so it can be shared by several servers.
    """

    def generate_nonce(self, request):
        """Generate a new nonce value.

        This method generates a new nonce value for the given request
        environment.  It will be a unique and non-forgable token containing
        only characters from the base64 alphabet.
        """
        raise NotImplementedError  # pragma: no cover

    def is_valid_nonce(self, nonce, request):
        """Check whether the given nonce is valid.

        This method returns True only if the given nonce was previously
        issued to the client sending the given request, and it if it has
        not become stale.
        """
        raise NotImplementedError  # pragma: no cover

    def get_next_nonce(self, nonce, request):
        """Get a new nonce to be used by the client for future requests.

        This method returns a new nonce that should be used by the client for
        future requests.  It may also return None if the given nonce is still
        valid and should be re-used.
        """
        raise NotImplementedError  # pragma: no cover

    def get_nonce_count(self, nonce):
        """Get the current client nonce-count.

        This method returns the most-recently-set client nonce-count, or
        None if not nonce-count has been set.
        """
        raise NotImplementedError  # pragma: no cover

    def set_nonce_count(self, nonce, nc):
        """Set the current client nonce-count.

        This method records the given value as the current nonce-count for
        that nonce.  Subsequent calls to get_nonce_count() will return it.
        The given nonce-count value should be an integer.
        """
        raise NotImplementedError  # pragma: no cover


class SignedNonceManager(object):
    """Class managing signed digest-auth nonces.

    This class provides a NonceManager implementation based on signed
    timestamped nonces.  It should provide a good balance between speed,
    memory-usage and security for most applications.

    The following options customize the use of this class:

       * secret:  string key used for signing the nonces;
                  if not specified then a random bytestring is used.

       * timeout: the time after which a nonce will expire.

       * soft_timeout:  the time after which an updated nonce will
                        be sent to the client.

       * sign_headers:  a list of environment keys to include in the
                        nonce signature; if not specified then it
                        defaults to just the user-agent string.
    """

    def __init__(self, secret=None, timeout=None, soft_timeout=None,
                 sign_headers=None):
        # Default secret is a random bytestring.
        if secret is None:
            secret = os.urandom(16)
        # Default timeout is five minutes.
        if timeout is None:
            timeout = 5 * 60
        # Default soft_timeout is 80% of the hard timeout.
        if soft_timeout is None:
            soft_timeout = int(timeout * 0.8) or None
        # Default signing headers are just the user-agent string.
        if sign_headers is None:
            sign_headers = ("HTTP_USER_AGENT",)
        self.secret = secret
        self.timeout = timeout
        self.soft_timeout = soft_timeout
        self.sign_headers = sign_headers
        # We need to keep a mapping from nonces to their most recent count.
        self._nonce_counts = {}
        # But we don't want to store nonces in memory forever!
        # We keep a queue of nonces and aggresively purge them when expired.
        # Unfortunately this requires a lock, but we go to some lengths
        # to avoid having to acquire it in the default case.  See the
        # set_nonce_count() method for the details.
        self._nonce_purge_lock = threading.Lock()
        self._nonce_purge_queue = []

    def generate_nonce(self, request):
        """Generate a new nonce value.

        In this implementation the nonce consists of an encoded timestamp
        and a HMAC signature to prevent forgery.  The signature can embed
        additional headers from the client request, to tie it to a particular
        user-agent.
        """
        # The nonce is the current time, hmac-signed along with the
        # request headers to tie it to a particular client or user-agent.
        timestamp = hex(int(time.time() * 10))
        # Remove hex-formatting guff e.g. "0x31220ead8L" => "31220ead8"
        timestamp = timestamp[2:]
        if timestamp.endswith("L"):
            timestamp = timestamp[:-1]
        sig = self._get_signature(timestamp, request)
        return "%s:%s" % (timestamp, sig)

    def is_valid_nonce(self, nonce, request):
        """Check whether the given nonce is valid.

        In this implementation the nonce is valid is if has a valid
        signature, and if the embedded timestamp is not too far in
        the past.
        """
        if self._nonce_has_expired(nonce):
            return False
        timestamp, sig = nonce.split(":", 1)
        expected_sig = self._get_signature(timestamp, request)
        # This is a deliberately slow string-compare to avoid timing attacks.
        # Read the docstring of strings_differ for more details.
        return not utils.strings_differ(sig, expected_sig)

    def get_next_nonce(self, nonce, request):
        """Get a new nonce to be used by the client for future requests.

        In this implementation a new nonce is issued whenever the current
        nonce is older than the soft timeout.
        """
        if not self._nonce_has_expired(nonce, self.soft_timeout):
            return None
        return self.generate_nonce(request)

    def get_nonce_count(self, nonce):
        """Get the current client nonce-count."""
        # No need to lock here.  If the client is generating lots of
        # parallel requests with the same nonce then we *might* read
        # a stale nonce count, but this will just trigger a re-submit
        # from the client and not produce any errors.
        return self._nonce_counts.get(nonce, None)

    def set_nonce_count(self, nonce, nc):
        """Set the current client nonce-count."""
        # If this is the first count registered for that nonce,
        # add it into the heap for expiry tracking.  Also take the
        # opportunity to remove a few expired nonces from memory.
        # In this way, we only spend time purging if we're about to
        # increase memory usage by registering a new nonce.
        if nonce not in self._nonce_counts:
            with self._nonce_purge_lock:
                self._purge_expired_nonces(limit=10)
                heapq.heappush(self._nonce_purge_queue, nonce)
        # Update the dict outside of the lock.  This is intentionally
        # a little sloppy, and may produce lost updates if the client
        # is sending parallel requests with the same nonce.  That's
        # not very likely and not very serious, and it's outweighed
        # by not having to take the lock in the common case.
        self._nonce_counts[nonce] = nc

    def _purge_expired_nonces(self, limit=None):
        """Purge any expired nonces from the in-memory store."""
        if limit is None:
            limit = len(self._nonce_purge_queue)
        # Pop nonces off the heap until we find one that's not expired.
        # Remove each expired nonce from the count map as we go.
        for i in xrange(min(limit, len(self._nonce_purge_queue))):
            nonce = self._nonce_purge_queue[0]
            if not self._nonce_has_expired(nonce):
                break
            self._nonce_counts.pop(nonce, None)
            heapq.heappop(self._nonce_purge_queue)

    def _nonce_has_expired(self, nonce, timeout=None):
        """Check whether the given nonce has expired."""
        if timeout is None:
            timeout = self.timeout
        try:
            timestamp, sig = nonce.split(":", 1)
            expiry_time = (int(timestamp, 16) * 0.1) + timeout
        except ValueError:
            # Eh? Malformed Nonce? Treat it as expired.
            return True
        else:
            return expiry_time <= time.time()

    def _get_signature(self, value, request):
        """Calculate the HMAC signature for the given value.

        This method will calculate the HMAC signature for an arbitrary
        string value, mixing in some headers from the request environment
        so that the signature is tied to a particular user-agent.
        """
        # We're using md5 for the digest; using something stronger
        # for the HMAC probably won't win us much.
        sig = hmac.new(self.secret, str_encode(value), md5)
        for header in self.sign_headers:
            sig.update(str_encode("\x00"))
            sig.update(str_encode(request.environ.get(header, "")))
        sig = base64.b64encode(sig.digest())
        if six.PY3:
            return sig.decode('ascii')
        else:
            return sig