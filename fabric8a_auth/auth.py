"""Auhentication helpers"""
import os
from functools import wraps

import jwt
import requests
from flask import app, current_app, request

from fabric8a_auth.errors import HTTPError


def decode_token(app, token, audiences=None, ):
    """Decode JWT tokens from auth service"""
    if token is None:
        return token

    if token.startswith('Bearer '):
        _, token = token.split(' ', 1)

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
            for audience in audiences:
                try:
                    decoded_token = jwt.decode(token, public_key, algorithms=['RS256'], audience=audience)
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

    return decoded_token


def decode_user_token(app, token):
    """Decode the authorization token read from the request header."""
    audiences = get_audiences()
    decoded_token = decode_token(app, token, audiences)

    if decoded_token is None:
        raise jwt.InvalidTokenError('Auth token cannot be verified.')
    if "email_verified" not in decoded_token:
        raise jwt.InvalidIssuerError('Can not retrieve the email_verified property from the token')
    if decoded_token["email_verified"] in ('0', 'False', 'false'):
        raise jwt.InvalidIssuerError('Email of the user has not been validated')

    return decoded_token


def decode_service_token(app, token):
    """Decode OSIO service token."""

    decoded_token = decode_token(app, token)

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


def fetch_public_keys(app):  # pragma: no cover
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
                keys[i] = \
                    '-----BEGIN PUBLIC KEY-----\n{pkey}\n' \
                    '-----END PUBLIC KEY-----'.format(pkey=key)

            app.public_keys = keys
        else:
            app.public_keys = None

    return app.public_keys


def init_service_account_token(app):
    """Initialize a service token from auth service."""
    auth_url = os.getenv('FABRIC8_AUTH_URL', '')
    endpoint = '{url}/api/token'.format(url=auth_url)

    client_id = os.getenv('SERVICE_ACCOUNT_CLIENT_ID', 'id')
    client_secret = os.getenv('SERVICE_ACCOUNT_CLIENT_SECRET', 'secret')

    payload = {"grant_type": "client_credentials",
               "client_id": client_id.strip(),
               "client_secret": client_secret.strip()}
    try:
        resp = requests.post(endpoint, json=payload)
    except requests.exceptions.RequestException as e:
        app.logger.error('Fetching Service Account token from %s, status %d, result: %s',
                         auth_url, resp.status_code, resp.text)
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
