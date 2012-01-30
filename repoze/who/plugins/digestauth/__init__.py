# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

A repoze.who plugin for authentication via HTTP-Digest-Auth:

    http://tools.ietf.org/html/rfc2617

"""


__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 1
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


from zope.interface import implements

from repoze.who.interfaces import IIdentifier, IChallenger, IAuthenticator
from repoze.who.utils import resolveDotted

from repoze.who.plugins.digestauth.noncemanager import SignedNonceManager
from repoze.who.plugins.digestauth.utils import (extract_digest_credentials,
                                                 calculate_pwdhash,
                                                 check_digest_response)


# WSGI environ key used to indicate a stale nonce.
_ENVKEY_STALE_NONCE = "repoze.who.plugins.digestauth.stale_nonce"


class DigestAuthPlugin(object):
    """A repoze.who plugin for authentication via HTTP-Digest-Auth.

    This plugin provides a repoze.who IIdentifier/IAuthenticator/IChallenger
    implementing HTTP's Digest Access Authentication protocol:

        http://tools.ietf.org/html/rfc2617

    When used as an IIdentifier, it will extract digest-auth credentials
    from the HTTP Authorization header, check that they are well-formed
    and fresh, and return them for checking by an IAuthenticator.

    When used as an IAuthenticator, it will validate digest-auth credentials
    using a callback function to obtain the user's password or password hash.

    When used as an IChallenger, it will issue a HTTP WWW-Authenticate
    header with a fresh digest-auth challenge for each challenge issued.

    This plugin implements fairly complete support for the protocol as defined
    in RFC-2167.  Specifically:

        * both qop="auth" and qop="auth-int" modes
        * compatability mode for legacy clients
        * client nonce-count checking
        * next-nonce generation via the Authentication-Info header

    The following optional parts of the specification are not supported:

        * MD5-sess, or any hash algorithm other than MD5
        * mutual authentication via the Authentication-Info header

    Also, for qop="auth-int" mode, this plugin assumes that the request
    contains a Content-MD5 header and that this header is validated by some
    other component of the system (as it would be very rude for an auth
    plugin to consume the request body to calculate this header itself).

    To implement nonce generation, storage and expiration, this plugin
    uses a helper object called a "nonce manager".  This allows the details
    of nonce management to be modified to meet the security needs of your
    deployment.  The default implementation (SignedNonceManager) should be
    suitable for most purposes.
    """

    implements(IIdentifier, IChallenger, IAuthenticator)

    def __init__(self, realm, nonce_manager=None, domain=None, qop=None,
                 get_password=None, get_pwdhash=None):
        if nonce_manager is None:
            nonce_manager = SignedNonceManager()
        if qop is None:
            qop = "auth"
        self.realm = realm
        self.nonce_manager = nonce_manager
        self.domain = domain
        self.qop = qop
        self.get_password = get_password
        self.get_pwdhash = get_pwdhash

    def identify(self, environ):
        """Extract HTTP-Digest-Auth credentials from the request.

        This method extracts the digest-auth credentials from the request
        and checks that the provided nonce and other metadata is valid.
        If the nonce is found to be invalid (e.g. it is being re-used)
        then None is returned.

        If the credentials are fresh then the returned identity is a dict
        containing all the digest-auth credentials necessary to validate the
        signature, e.g.:

            {'username': 'user',
             'nonce': 'fc19cc22d1b5f84d',
             'realm': 'Sync',
             'algorithm': 'MD5',
             'qop': 'auth',
             'cnonce': 'd61391b0baeb5131',
             'nc': '00000001',
             'uri': '/some-protected-uri',
             'request-method': 'GET',
             'response': '75a8f0d4627eef8c73c3ac64a4b2acca'}

        It is the responsibility of an IAuthenticator plugin to check that
        the "response" value is a correct digest calculated according to the
        provided credentials.
        """
        # Grab the credentials out of the environment.
        identity = extract_digest_credentials(environ)
        if identity is None:
            return None
        # Check that they're for the expected realm.
        if identity["realm"] != self.realm:
            return None
        # Check that the provided nonce is valid.
        # If this looks like a stale request, mark it in the environment
        # so we can include that information in the challenge.
        nonce = identity["nonce"]
        if not self.nonce_manager.is_valid_nonce(nonce, environ):
            environ[_ENVKEY_STALE_NONCE] = True
            return None
        # Check that the nonce-count is strictly increasing.
        # We store them as integers since that takes less memory than strings.
        nc_old = self.nonce_manager.get_nonce_count(nonce)
        if nc_old is not None:
            nc_new = identity.get("nc", None)
            if nc_new is None or int(nc_new, 16) <= nc_old:
                environ[_ENVKEY_STALE_NONCE] = True
                return None
        # Looks good!
        return identity

    def remember(self, environ, identity):
        """Remember the authenticated identity.

        This method records an updated nonce-count for the given identity.
        By only updating the nonce-count if the request is successfully
        authenticated, we reduce the risk of a DOS via memory exhaustion.

        This method can be used to pre-emptively send an updated nonce to
        the client as part of a successful response.
        """
        nonce = identity.get("nonce", None)
        if nonce is None:
            return None
        # Update the nonce-count if given.
        nc_new = identity.get("nc", None)
        if nc_new is not None:
            self.nonce_manager.record_nonce_count(nonce, int(nc_new, 16))
        # Send an updated nonce if required.
        next_nonce = self.nonce_manager.get_next_nonce(nonce, environ)
        if next_nonce is None:
            return None
        next_nonce = next_nonce.replace('"', '\\"')
        value = 'nextnonce="%s"' % (next_nonce,)
        return [("Authentication-Info", value)]

    def forget(self, environ, identity):
        """Forget the authenticated identity.

        For digest auth this is equivalent to sending a new challenge header,
        which should cause the user-agent to re-prompt for credentials.
        """
        return self._get_challenge_headers(environ, check_stale=False)

    def authenticate(self, environ, identity):
        """Authenticate the provided identity.

        If one of the "get_password" or "get_pwdhash" callbacks were provided
        then this class is capable of authenticating the identity for itself.
        It will calculate the expected digest response and compare it to that
        provided by the client.  The client is authenticated only if it has
        provided the correct response.
        """
        # Grab the username.
        # If there isn't one, we can't use this identity.
        username = identity.get("username")
        if username is None:
            return None
        # Grab the realm.
        # If there isn't one or it doesn't match, we can't use this identity.
        realm = identity.get("realm")
        if realm is None or realm != self.realm:
            return None
        # Obtain the pwdhash via one of the callbacks.
        if self.get_pwdhash is not None:
            pwdhash = self.get_pwdhash(username, realm)
        elif self.get_password is not None:
            password = self.get_password(username)
            pwdhash = calculate_pwdhash(username, password, realm)
        else:
            return None
        # Validate the digest response.
        if not check_digest_response(identity, pwdhash=pwdhash):
            return None
        # Looks good!
        return username

    def challenge(self, environ, status, app_headers, forget_headers):
        """Challenge for digest-auth credentials.

        For digest-auth the challenge is a "401 Unauthorized" response with
        a fresh nonce in the WWW-Authenticate header.
        """
        headers = self._get_challenge_headers(environ)
        headers.extend(app_headers)
        headers.extend(forget_headers)
        if not status.startswith("401 "):
            status = "401 Unauthorized"

        def challenge_app(environ, start_response):
            start_response(status, headers)
            return ["Unauthorized"]

        return challenge_app

    def _get_challenge_headers(self, environ, check_stale=True):
        """Get headers necessary for a fresh digest-auth challenge.

        This method generates a new digest-auth challenge for the given
        request environ, including a fresh nonce.  If the environment
        is marked as having a stale nonce then this is indicated in the
        challenge.
        """
        params = {}
        params["realm"] = self.realm
        params["qop"] = self.qop
        params["nonce"] = self.nonce_manager.generate_nonce(environ)
        if self.domain is not None:
            params["domain"] = self.domain
        # Escape any special characters in those values, so we can send
        # them as quoted-strings.  The extra values added below are under
        # our control so we know they don't contain quotes.
        for key, value in params.iteritems():
            params[key] = value.replace('"', '\\"')
        # Mark the nonce as stale if told so by the environment.
        # NOTE:  The RFC says the server "should only set stale to TRUE if
        # it receives a request for which the nonce is invalid but with a
        # valid digest for that nonce".  But we can't necessarily check the
        # password at this stage, and it's only a "should", so don't bother.
        if check_stale and environ.get(_ENVKEY_STALE_NONCE):
            params["stale"] = "TRUE"
        params["algorithm"] = "MD5"
        # Construct the final header as quoted-string k/v pairs.
        value = ", ".join('%s="%s"' % itm for itm in params.iteritems())
        value = "Digest " + value
        return [("WWW-Authenticate", value)]


def make_plugin(realm='', nonce_manager=None, domain=None, qop=None,
                get_password=None, get_pwdhash=None):
    """Make a DigestAuthPlugin using values from a .ini config file.

    This is a helper function for loading a DigestAuthPlugin via the
    repoze.who .ini config file system.  It converts its arguments from
    strings to the appropriate type then passes them on to the plugin.
    """
    if isinstance(nonce_manager, basestring):
        nonce_manager = resolveDotted(nonce_manager)
        if callable(nonce_manager):
            nonce_manager = nonce_manager()
    if isinstance(get_password, basestring):
        get_password = resolveDotted(get_password)
        if get_password is not None:
            assert callable(get_password)
    if isinstance(get_pwdhash, basestring):
        get_pwdhash = resolveDotted(get_pwdhash)
        if get_pwdhash is not None:
            assert callable(get_pwdhash)
    plugin = DigestAuthPlugin(realm, nonce_manager, domain, qop,
                              get_password, get_pwdhash)
    return plugin
