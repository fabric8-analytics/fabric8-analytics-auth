"""Authentication helpers."""

import datetime
import enum
from os import getenv

from flask import current_app, request, g
from flask_security import current_user
from requests import get, post, exceptions
from itsdangerous import BadSignature, SignatureExpired, TimedJSONWebSignatureSerializer
import jwt
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from errors import HTTPError

jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))


def fetch_public_key(app):
    """Get public key and caches it on the app object for future use."""
    # TODO: even though saving the key on the app object is not very nice,
    #  it's actually safe - the worst thing that can happen is that we will
    #  fetch and save the same value on the app object multiple times
    if not getattr(app, 'public_key', ''):
        keycloak_url = app.config.get('BAYESIAN_FETCH_PUBLIC_KEY', '')
        if keycloak_url:
            pub_key_url = keycloak_url.strip('/') + '/auth/realms/fabric8/'
            try:
                result = get(pub_key_url, timeout=0.5)
                app.logger.info('Fetching public key from %s, status %d, result: %s',
                                pub_key_url, result.status_code, result.text)
            except exceptions.Timeout:
                app.logger.error('Timeout fetching public key from %s', pub_key_url)
                return ''
            if result.status_code != 200:
                return ''
            pkey = result.json().get('public_key', '')
            app.public_key = \
                '-----BEGIN PUBLIC KEY-----\n{pkey}\n-----END PUBLIC KEY-----'.format(pkey=pkey)
        else:
            app.public_key = app.config.get('BAYESIAN_PUBLIC_KEY')

    return app.public_key


def get_audiences():
    """Retrieve all JWT audiences."""
    return current_app.config.get('BAYESIAN_JWT_AUDIENCE').split(',')


def decode_token(token):
    """Decode the authorization token passed in parameter."""
    if token is None:
        return {}

    if token.startswith('Bearer '):
        _, token = token.split(' ', 1)

    pub_key = fetch_public_key(current_app)
    audiences = get_audiences()

    decoded_token = None

    for aud in audiences:
        try:
            decoded_token = jwt.decode(token, pub_key, audience=aud)
        except jwt.InvalidTokenError:
            decoded_token = None
            current_app.logger.error(
                'Auth Token could not be decoded for audience {}'.format(aud))

        if decoded_token is not None:
            break

    if decoded_token is None:
        raise jwt.InvalidTokenError('Auth token audience cannot be verified.')
    if "email_verified" not in decoded_token:
        raise jwt.InvalidIssuerError('Can not retrieve the email_verified property from the token')
    if decoded_token["email_verified"] in ('0', 'False', 'false'):
        raise jwt.InvalidIssuerError('Email of the user has not been validated')

    return decoded_token


def get_token_from_auth_header():
    """Get the authorization token read from the request header."""
    return request.headers.get('Authorization')


def login_required(view):
    """Check if the login is required and if the user can be authorized."""
    def wrapper(*args, **kwargs):
        """Check if the login is required and if the user can be authorized."""
        # Disable authentication for local setup
        if getenv('DISABLE_AUTHENTICATION') in ('1', 'True', 'true'):
            return view(*args, **kwargs)

        logger = current_app.logger
        user = None

        try:
            token = get_token_from_auth_header()
            decoded = decode_token(token)
            if not decoded:
                logger.exception('Provide an Authorization token with the API request')
                raise HTTPError(401, 'Authentication failed - token missing')

            logger.info('Successfuly authenticated user {e} using JWT'.format(
                e=decoded.get('email')))
        except jwt.ExpiredSignatureError as exc:
            logger.exception('Expired JWT token')
            decoded = {'email': 'unauthenticated@jwt.failed'}
            raise HTTPError(401, 'Authentication failed - token has expired') from exc
        except Exception as exc:
            logger.exception('Failed decoding JWT token')
            decoded = {'email': 'unauthenticated@jwt.failed'}
            raise HTTPError(401, 'Authentication failed - could not decode JWT token') from exc
        else:
            user = APIUser(decoded.get('email', 'nobody@nowhere.nodomain'))

        if user:
            g.current_user = user
        else:
            g.current_user = APIUser('unauthenticated@no.auth.token')
            raise HTTPError(401, 'Authentication required')
        return view(*args, **kwargs)
    return wrapper


class User:
    """Class that represents User entity."""

    def __init__(self, email):
        """Construct the instance of APIUsed class and initialize the 'email' attribute."""
        self.email = email
