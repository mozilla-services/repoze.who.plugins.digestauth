# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Helper functions for repoze.who.plugins.digestauth.

"""

import re
import base64
import wsgiref.util
from urlparse import urlparse
from hashlib import md5


# Regular expression matching a single param in the HTTP_AUTHORIZATION header.
# This is basically <name>=<value> where <value> can be an unquoted token,
# an empty quoted string, or a quoted string where the ending quote is *not*
# preceded by a backslash.
_AUTH_PARAM_RE = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
_AUTH_PARAM_RE = re.compile(r"^\s*" + _AUTH_PARAM_RE + r"\s*$")

# Regular expression matching an unescaped quote character.
_UNESC_QUOTE_RE = r'(^")|([^\\]")'
_UNESC_QUOTE_RE = re.compile(_UNESC_QUOTE_RE)

# Regular expression matching a backslash-escaped characer.
_ESCAPED_CHAR = re.compile(r"\\.")


def parse_auth_header(value):
    """Parse an authorization header string into an identity dict.

    This function can be used to parse the value from an Authorization
    header into a dict of its constituent parameters.  The auth scheme
    name will be included under the key "scheme", and any other auth
    creds will appear as keys in the dictionary.

    For example, given the following auth header value:

        'Digest realm="Sync" userame=user1 response="123456"'

    This function will return the following dict:

        {"scheme": "Digest", realm: "Sync",
         "username": "user1", "response": "123456"}

    """
    scheme, kvpairs_str = value.split(None, 1)
    # Split the parameters string into individual key=value pairs.
    # In the simple case we can just split by commas to get each pair.
    # Unfortunately this will break if one of the values contains a comma.
    # So if we find a component that isn't a well-formed key=value pair,
    # then we stitch bits back onto the end of it until it is.
    kvpairs = []
    if kvpairs_str:
        for kvpair in kvpairs_str.split(","):
            if not kvpairs or _AUTH_PARAM_RE.match(kvpairs[-1]):
                kvpairs.append(kvpair)
            else:
                kvpairs[-1] = kvpairs[-1] + "," + kvpair
        if not _AUTH_PARAM_RE.match(kvpairs[-1]):
            raise ValueError('Malformed auth parameters')
    # Now we can just split by the equal-sign to get each key and value.
    creds = {"scheme": scheme}
    for kvpair in kvpairs:
        (key, value) = kvpair.strip().split("=", 1)
        # For quoted strings, remove quotes and backslash-escapes.
        if value.startswith('"'):
            value = value[1:-1]
            if _UNESC_QUOTE_RE.search(value):
                raise ValueError("Unescaped quote in quoted-string")
            value = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], value)
        creds[key] = value
    return creds


def extract_digest_credentials(environ):
    """Extract digest credentials from the given request environment.

    This function extracts the HTTP-Digest-Auth credentials from the given
    request environment, performs some sanity checks, and returns them as
    a dict.  If the credentials are missing or invalid, None is returned.
    """
    # Grab the auth credentials, if any.
    authz = environ.get("HTTP_AUTHORIZATION")
    if authz is None:
        return None
    # Parse out the dict of credentials credentials.
    try:
        creds = parse_auth_header(authz)
    except ValueError:
        return None
    if creds["scheme"].lower() != "digest":
        return None
    # Check that there's nothing broken or missing.
    if not validate_digest_parameters(creds):
        return None
    # Check that the reported uri matches the request URI
    if not validate_digest_uri(creds, environ):
        return None
    # Include extra information from the request itself.
    creds["request-method"] = environ["REQUEST_METHOD"]
    if creds.get("qop") == "auth-int":
        creds["content-md5"] = environ["HTTP_CONTENT_MD5"]
    return creds


def validate_digest_parameters(creds):
    """Validate that credentials contain valid digest-auth parameters.

    This function provides a basic sanity-check on the given digest-auth
    credentials.  It checks that they're well-formed and are not missing
    any parameters, but doesn't actually provide any authentication.

    Returns True if the parameters are valid, False if not.
    """
    # Check that we have all the basic information.
    for key in ("username", "realm", "nonce", "uri", "response"):
        if key not in creds:
            return False
    # Check for extra information required when "qop" is present.
    if "qop" in creds:
        for key in ("cnonce", "nc"):
            if key not in creds:
                return False
        if creds["qop"] not in ("auth", "auth-int"):
            return False
        # RFC-2617 says the nonce-count must be an 8-char-long hex number.
        # We enforce the length limit strictly since flooding the server with
        # many large nonce-counts could cause a DOS via memory exhaustion.
        if len(creds["nc"]) > 8:
            return False
        try:
            int(creds["nc"], 16)
        except ValueError:
            return False
    # Check that the algorithm, if present, is explcitly set to MD5.
    if "algorithm" in creds and creds["algorithm"].lower() != "md5":
        return False
    # Looks good!
    return True


def validate_digest_uri(creds, environ, msie_hack=True):
    """Validate that the digest URI matches the request environment.

    This is a helper function to check that digest-auth is being applied
    to the correct URI.  It matches the given request environment against
    the URI specified in the digest auth credentials, returning True if
    they are equiavlent and False otherwise.

    Older versions of MSIE are known to handle certain URIs incorrectly,
    and this function includes a hack to work around this problem.  To
    disable it and sligtly increase security, pass msie_hack=False.
    """
    uri = creds["uri"]
    req_uri = wsgiref.util.request_uri(environ)
    if uri != req_uri:
        p_req_uri = urlparse(req_uri)
        if not p_req_uri.query:
            if uri != p_req_uri.path:
                return False
        else:
            if uri != "%s?%s" % (p_req_uri.path, p_req_uri.query):
                # MSIE < 7 doesn't include the GET vars in the signed URI.
                # Let them in, but don't give other user-agents a free ride.
                if not msie_hack:
                    return False
                if "MSIE" not in environ.get("HTTP_USER_AGENT", ""):
                    return False
                if uri != p_req_uri.path:
                    return False
    return True


def calculate_pwdhash(username, password, realm):
    """Calculate the password hash used for digest auth.

    This function takes the username, password and realm and calculates
    the password hash (aka "HA1") used in the digest-auth protocol.
    It assumes that the hash algorithm is MD5.
    """
    data = "%s:%s:%s" % (username, realm, password)
    return md5(data).hexdigest()


def calculate_reqhash(creds):
    """Calculate the request hash used for digest auth.

    This function takes the digest auth credentials and calculates the
    request hash (aka "HA2") used in the digest-auth protocol.  It assumes
    that the hash algorithm is MD5.
    """
    method = creds["request-method"]
    uri = creds["uri"]
    qop = creds.get("qop")
    # For qop="auth" or unspecified, we just has the method and uri.
    if qop in (None, "auth"):
        data = "%s:%s" % (method, uri)
    # For qop="auth-int" we also include the md5 of the entity body.
    # We assume that a Content-MD5 header has been sent and is being
    # checked by some other layer in the stack.
    elif qop == "auth-int":
        content_md5 = creds["content-md5"]
        content_md5 = base64.b64decode(content_md5)
        data = "%s:%s:%s" % (method, uri, content_md5)
    # No other qop values are recognised.
    else:
        raise ValueError("unrecognised qop value: %r" % (qop,))
    return md5(data).hexdigest()


def calculate_digest_response(creds, pwdhash=None, password=None):
    """Calculate the expected response to a digest challenge.

    Given the digest challenge credentials and the user's password or
    password hash, this function calculates the expected digest response
    according to RFC-2617.  It assumes that the hash algorithm is MD5.
    """
    username = creds["username"]
    realm = creds["realm"]
    if pwdhash is None:
        if password is None:
            raise ValueError("must provide either 'pwdhash' or 'password'")
        pwdhash = calculate_pwdhash(username, password, realm)
    reqhash = calculate_reqhash(creds)
    qop = creds.get("qop")
    if qop is None:
        data = "%s:%s:%s" % (pwdhash, creds["nonce"], reqhash)
    else:
        data = ":".join([pwdhash, creds["nonce"], creds["nc"],
                         creds["cnonce"], qop, reqhash])
    return md5(data).hexdigest()


def check_digest_response(creds, pwdhash=None, password=None):
    """Check if the given digest response is valid.

    This function checks whether a dict of digest response credentials
    has been correctly authenticated using the specified password or
    password hash.
    """
    expected = calculate_digest_response(creds, pwdhash)
    # Use a timing-invarient comparison to prevent guessing the correct
    # digest one character at a time.  Ideally we would reject repeated
    # attempts to use the same nonce, but that may not be possible using
    # e.g. time-based nonces.  This is a nice extra safeguard.
    return not strings_differ(expected, creds["response"])


def strings_differ(string1, string2):
    """Check whether two strings differ while avoiding timing attacks.

    This function returns True if the given strings differ and False
    if they are equal.  It's careful not to leak information about *where*
    they differ as a result of its running time, which can be very important
    to avoid certain timing-related crypto attacks:

        http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf

    """
    if len(string1) != len(string2):
        return True
    invalid_bits = 0
    for a, b in zip(string1, string2):
        invalid_bits += a != b
    return invalid_bits != 0
