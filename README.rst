=============================
repoze.who.plugins.digestauth
=============================

This is repoze.who plugin implementing HTTP's Digest Access Authentication
as per RFC-2617:

    http://tools.ietf.org/html/rfc2617

It provides good support for the protocol as it is typically used in the
wild:

    * both qop="auth" and qop="auth-int" modes
    * compatability mode for legacy clients
    * client nonce-count checking
    * next-nonce generation via the Authentication-Info header

The following features of the protocol are rarely supported by HTTP clients
and thus have not yet been implemented:

    * MD5-sess, or any hash algorithm other than MD5
    * mutual authentication via the Authentication-Info header


Configuration
=============

Configuration of the digest-auth plugin can be done from the standard 
repoze.who config file like so::

    [plugin:digestauth]
    use = repoze.who.plugins.digestauth:make_plugin
    realm = MyRealm
    get_pwdhash = mymodule:get_pwdhash

The following configuration options are available:

    * realm:  the realm string; included verbatim in the challenge header
    * domain:  the domain string; included verbatim in the challenge header
    * qop:  the desired quality of protection ("auth" or "auth-int")  
    * get_password:  dotted name of a callback to get the user's password
    * get_pwdhash:  dotted name of a callback to get the user's password hash
    * nonce_manager:  dotted name of a class to use for nonce management


Authentication
==============

To authenticate a user via Digest Auth, this plugin needs access to either
their raw password or their "password hash", which is the MD5 digest of their
username, password and authentication realm::

    def calculate_pwdhash(username, password, realm):
        return md5("%s:%s:%s" % (username, realm, password)).hexdigest()

You must provide the callback function "get_password" or "get_pwdhash" to
the DigestAuthPlugin.


Nonce Management
================

The security of Digest Access Authentication depends crucially on the secure
generation and managent of cryptographic nonces.  In order to prevent replay
attacks the server must reject requests that have a repeated nonce.

The details of nonce management have been extracted into a separate interface,
defined by the repoze.who.plugins.digestauth.noncemanager:NonceManager class.
The default implementation uses HMAC-signed tokens and an in-memory cache of
recently seen nonce counts.  If you have more particular needs you might like
to implement your own NonceManager subclass.
