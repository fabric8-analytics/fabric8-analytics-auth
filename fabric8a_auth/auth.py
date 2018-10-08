"""Authentication helpers."""
import os
from functools import wraps

import jwt
import requests
from flask import current_app, request, g

from fabric8a_auth.errors import AuthError


def decode_token(app, token, audiences=None):
    """Decode JWT tokens from auth service."""
    if token is None:
        return token

    if token.startswith('Bearer '):
        _, token = token.split(' ', 1)

    decoded_token = None

    pub_keys = fetch_public_keys(app)
    for pub_key in pub_keys:
        public_key = pub_key.get("key", "")

        if audiences is None:
            # Service account does not have audiences
            try:
                decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
            except jwt.InvalidTokenError:
                app.logger.error("Service account token couldn't be decoded, token is invalid")
                decoded_token = None
            except jwt.InvalidSignatureError:
                app.logger.error("Service account token couldn't be decoded, signature is invalid")
                decoded_token = None
        else:
            # For User account check if the audience is valid
            try:
                decoded_token = jwt.decode(token, public_key,
                                           algorithms=['RS256'],
                                           audience=audiences)
            except jwt.exceptions.InvalidAudienceError:
                app.logger.error("User auth token couldn't be decoded, audience is invalid")
                decoded_token = None
            except jwt.InvalidTokenError:
                app.logger.error("User auth token couldn't be decoded, token is invalid")
                decoded_token = None
            except jwt.InvalidSignatureError:
                app.logger.error("User auth token couldn't be decoded, signature is invalid")
                decoded_token = None

        if decoded_token:
            break

    g.decoded_token = decoded_token or {}
    return decoded_token


def decode_user_token(app, token):
    """Decode the authorization token read from the request header."""
    audiences = get_audiences()
    decoded_token = decode_token(app, token, audiences)

    return decoded_token


def decode_service_token(app, token):
    """Decode OSIO service token."""
    decoded_token = decode_token(app, token)

    return decoded_token


def get_token_from_auth_header():
    """Get the authorization token read from the request header."""
    return request.headers.get('Authorization')


def get_threescale_account_secret_header():
    """Get the 3scale account secret read from the request header."""
    return request.headers.get('x-3scale-account-secret')


def get_audiences():
    """Retrieve all JWT audiences."""
    return os.environ.get('FABRIC8_ANALYTICS_JWT_AUDIENCE', '').split(',')


def login_required(view):
    """Check if the login is required and if the user can be authorized."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if is_authentication_disabled():
            return view(*args, **kwargs)

        lgr = current_app.logger

        threescale_account_secret = get_threescale_account_secret_header()
        if threescale_account_secret is not None:
            if os.getenv('THREESCALE_ACCOUNT_SECRET') == threescale_account_secret:
                lgr.info('Request has been successfully authenticated')
            else:
                return AuthError(401, 'Authentication failed - invalid token received')
        else:
            try:
                decoded = decode_user_token(current_app, get_token_from_auth_header())
                if not decoded:
                    lgr.error('Provide an Authorization token with the API request')
                    return AuthError(401, 'Authentication failed - token missing')
                elif "email_verified" not in decoded:
                    return AuthError(401, 'Can not retrieve the '
                                         'email_verified property from the token')
                elif decoded["email_verified"] in ('0', 'False', 'false'):
                    return AuthError(401, 'Email of the user has not been validated')
                lgr.info('Successfully authenticated user {e} using JWT'.
                         format(e=decoded.get('email')))
            except jwt.ExpiredSignatureError:
                lgr.error('Expired JWT token')
                return AuthError(401, 'Authentication failed - token has expired')
            except Exception as exc:
                lgr.error('Failed with exception')
                return exc

        return view(*args, **kwargs)

    return wrapper


def service_token_required(view):
    """Check if the request contains a valid service token."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if is_authentication_disabled():
            return view(*args, **kwargs)

        lgr = current_app.logger

        try:
            decoded = decode_service_token(current_app, get_token_from_auth_header())
            if not decoded:
                lgr.error('Provide an Authorization token with the API request')
                return AuthError(401, 'Authentication failed - token missing')

            lgr.info('Successfully authenticated user {e} using JWT'.
                     format(e=decoded.get('email')))
        except jwt.ExpiredSignatureError:
            lgr.error('Expired JWT token')
            return AuthError(401, 'Authentication failed - token has expired')
        except Exception as ex:
            lgr.error('Exception occured: {e}'.format(e=ex.msg))
            return ex

        return view(*args, **kwargs)

    return wrapper


def fetch_public_keys(app):
    """Get public keys for OSIO service account. Currently, there are three public keys."""
    if not getattr(app, "public_keys", []):
        auth_url = os.environ.get('OSIO_AUTH_URL')
        if auth_url:
            try:
                auth_url = auth_url.strip('/') + '/api/token/keys?format=pem'
                result = requests.get(auth_url, timeout=2)
                app.logger.info('Fetching public key from %s, status %d, result: %s',
                                auth_url, result.status_code, result.text)
            except requests.exceptions.Timeout:
                app.logger.error('Timeout fetching public key from %s', auth_url)
                return []
            if result.status_code != 200:
                return []

            keys = result.json().get('keys', [])
            for key_dict in keys:
                key = key_dict.get('key', '')
                key_dict['key'] = \
                    '-----BEGIN PUBLIC KEY-----\n{pkey}\n' \
                    '-----END PUBLIC KEY-----'.format(pkey=key)

            app.public_keys = keys
        else:
            app.public_keys = []

    return app.public_keys


def init_service_account_token(app):
    """Initialize a service token from auth service."""
    auth_url = os.environ.get('OSIO_AUTH_URL', '')
    endpoint = '{url}/api/token'.format(url=auth_url)

    client_id = os.environ.get('SERVICE_ACCOUNT_CLIENT_ID', 'id')
    client_secret = os.environ.get('SERVICE_ACCOUNT_CLIENT_SECRET', 'secret')

    payload = {"grant_type": "client_credentials",
               "client_id": client_id.strip(),
               "client_secret": client_secret.strip()}
    try:
        resp = requests.post(endpoint, json=payload)
    except requests.exceptions.RequestException as e:
        app.logger.error('Fetching Service Account token from %s, result: %s',
                         auth_url, str(e))
        raise e

    if resp.status_code == 200:
        data = resp.json()
        try:
            access_token = data['access_token']
        except IndexError:
            app.logger.error('JSON data does not contain access token %s', data)
            raise requests.exceptions.RequestException
        return access_token
    else:
        app.logger.error('Failed. Response code from auth service was: %s', resp.status_code)
        raise requests.exceptions.RequestException


def is_authentication_disabled():
    """Check if authentication is enabled."""
    if os.environ.get('DISABLE_AUTHENTICATION') in ('1', 'True', 'true'):
        return True
    else:
        return False
