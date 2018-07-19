"""Auhentication helpers"""
import os

from functools import wraps
import jwt
import requests
from flask import current_app, request
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm

from fabric8a_auth.errors import HTTPError

jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))


def get_audiences():
    """Retrieve all JWT audiences."""
    return current_app.config.get('FABRIC8_ANALYTICS_JWT_AUDIENCE').split(',')


def decode_user_token(token):
    """Decode the authorization token read from the request header."""
    if token is None:
        return {}

    if token.startswith('Bearer '):
        _, token = token.split(' ', 1)

    pub_key = fetch_public_key(current_app)
    audiences = get_audiences()
    decoded_token = None

    for aud in audiences:
        try:
            decoded_token = jwt.decode(token, pub_key, algorithms=['RS256'], audience=aud)
        except jwt.InvalidTokenError:
            current_app.logger.error('Auth Token could not be decoded for audience {}'.format(aud))
            decoded_token = None

        if decoded_token is not None:
            break

    if decoded_token is None:
        raise jwt.InvalidTokenError('Auth token audience cannot be verified.')
    if "email_verified" not in decoded_token:
        raise jwt.InvalidIssuerError('Can not retrieve the email_verified property from the token')
    if decoded_token["email_verified"] in ('0', 'False', 'false'):
        raise jwt.InvalidIssuerError('Email of the user has not been validated')

    return decoded_token


def decode_service_token(token):
    """Decode OSIO service token."""
    # TODO: Merge this function and user token function once audience is removed from user tokens.
    if token is None:
        return {}

    if token.startswith('Bearer '):
        _, token = token.split(' ', 1)

    pub_keys = fetch_public_keys(current_app)
    decoded_token = None

    # Since we have multiple public keys, we need to verify against every public key.
    # Token can be decoded by any one of the available public keys.
    for pub_key in pub_keys:
        try:
            pub_key = pub_key.get("key", "")
            decoded_token = jwt.decode(token, pub_key, algorithms=['RS256'])
        except jwt.InvalidTokenError:
            current_app.logger.error("Auth token couldn't be decoded for public key: {}"
                                     .format(pub_key))
            decoded_token = None

        if decoded_token:
            break

    if not decoded_token:
        raise jwt.InvalidTokenError('Auth token cannot be verified.')

    return decoded_token


def get_token_from_auth_header():
    """Get the authorization token read from the request header."""
    return request.headers.get('Authorization')


def get_audiences():
    """Retrieve all JWT audiences."""
    return os.getenv('FABRIC8_ANALYTICS_JWT_AUDIENCE').split(',')


def login_required(view):
    """Check if the login is required and if the user can be authorized."""
    # NOTE: the actual authentication 401 failures are commented out for now and will be
    # uncommented as soon as we know everything works fine; right now this is purely for
    # being able to tail logs and see if stuff is going fine
    @wraps(view)
    def wrapper(*args, **kwargs):
        # Disable authentication for local setup
        if os.getenv('DISABLE_AUTHENTICATION') in ('1', 'True', 'true'):
            return view(*args, **kwargs)

        lgr = current_app.logger

        try:
            decoded = decode_user_token(get_token_from_auth_header())
            if not decoded:
                lgr.exception('Provide an Authorization token with the API request')
                raise HTTPError(401, 'Authentication failed - token missing')

            lgr.info('Successfuly authenticated user {e} using JWT'.
                     format(e=decoded.get('email')))
        except jwt.ExpiredSignatureError as exc:
            lgr.exception('Expired JWT token')
            raise HTTPError(401, 'Authentication failed - token has expired') from exc
        except Exception as exc:
            lgr.exception('Failed decoding JWT token')
            raise HTTPError(401, 'Authentication failed - could not decode JWT token') from exc

        return view(*args, **kwargs)

    return wrapper


def service_token_required(view):
    """Check if the request contains a valid service token."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        # Disable authentication for local setup
        if os.getenv('DISABLE_AUTHENTICATION') in ('1', 'True', 'true'):
            return view(*args, **kwargs)

        lgr = current_app.logger

        try:
            decoded = decode_service_token(get_token_from_auth_header())
            if not decoded:
                lgr.exception('Provide an Authorization token with the API request')
                raise HTTPError(401, 'Authentication failed - token missing')

            lgr.info('Successfuly authenticated user {e} using JWT'.
                     format(e=decoded.get('email')))
        except jwt.ExpiredSignatureError as exc:
            lgr.exception('Expired JWT token')
            raise HTTPError(401, 'Authentication failed - token has expired') from exc
        except Exception as exc:
            lgr.exception('Failed decoding JWT token')
            raise HTTPError(401, 'Authentication failed - could not decode JWT token') from exc

        return view(*args, **kwargs)
    return wrapper


def fetch_public_key(app):
    """Get public key and caches it on the app object for future use."""
    # TODO: even though saving the key on the app object is not very nice,
    #  it's actually safe - the worst thing that can happen is that we will
    #  fetch and save the same value on the app object multiple times
    if not getattr(app, 'public_key', ''):
        keycloak_url = os.os.getenv('FABRIC8_ANALYTICS_FETCH_PUBLIC_KEY', '')
        if keycloak_url:
            pub_key_url = keycloak_url.strip('/') + '/auth/realms/fabric8/'
            try:
                result = requests.get(pub_key_url, timeout=0.5)
                app.logger.info('Fetching public key from %s, status %d, result: %s',
                                pub_key_url, result.status_code, result.text)
            except requests.exceptions.Timeout:
                app.logger.error('Timeout fetching public key from %s', pub_key_url)
                return ''
            if result.status_code != 200:
                return ''
            pkey = result.json().get('public_key', '')
            app.public_key = \
                '-----BEGIN PUBLIC KEY-----\n{pkey}\n' \
                '-----END PUBLIC KEY-----'.format(pkey=pkey)
        else:
            app.public_key = None

    return app.public_key


def fetch_public_keys(app):
    """Get public keys for OSIO service account. Currently, there are three public keys."""
    if not getattr(app, "service_public_keys", []):
        auth_url = os.os.getenv('FABRIC8_AUTH_URL', '')
        if auth_url:
            try:
                auth_url = auth_url.strip('/') + '/api/token/keys?format=pem'
                result = requests.get(auth_url, timeout=0.5)
                app.logger.info('Fetching public key from %s, status %d, result: %s',
                                auth_url, result.status_code, result.text)
            except requests.exceptions.Timeout:
                app.logger.error('Timeout fetching public key from %s', auth_url)
                return ''
            if result.status_code != 200:
                return ''

            keys = result.json().get('keys', [])

            for i, key in keys:
                keys[i] =\
                    '-----BEGIN PUBLIC KEY-----\n{pkey}\n' \
                    '-----END PUBLIC KEY-----'.format(pkey=key)

        else:
            app.service_public_keys = None

    return app.service_public_keys


class User:
    """Class that represents User entity."""

    def __init__(self, email):
        self.email = email
