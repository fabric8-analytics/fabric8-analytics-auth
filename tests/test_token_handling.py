"""Unit tests for token handling functions."""
import json
import os
from unittest.mock import patch

import jwt
import pytest
from flask import Flask

from fabric8a_auth.auth import decode_user_token, decode_service_token, \
    init_service_account_token, fetch_public_keys, service_token_required, login_required
from fabric8a_auth.errors import AuthError


def create_app():
    """Return flask app instance."""
    app = Flask(__name__)
    ctx = app.app_context()
    ctx.push()

    return app


def setup_module(module):
    """Perform setup of any state specific to the execution of the given module."""
    global APP
    global PRIVATE_KEY
    global PUBLIC_KEY
    global WRONG_PUBLIC_KEY
    global FABRIC8_AUTH_URL
    global SERVICE_ACCOUNT_CLIENT_ID
    global SERVICE_ACCOUNT_CLIENT_SECRET

    assert module is not None

    FABRIC8_AUTH_URL = "http://someurl.com/api/token"

    SERVICE_ACCOUNT_CLIENT_ID = "client_test_id"
    SERVICE_ACCOUNT_CLIENT_SECRET = "client test secret"

    # private and public key used in tests
    with open("private_key.pem") as fin:
        PRIVATE_KEY = fin.read()

    with open("public_key.pem") as fin:
        PUBLIC_KEY = fin.read()

    with open("wrong_public_key.pem") as fin:
        WRONG_PUBLIC_KEY = fin.read()

    APP = create_app()


def teardown_module(module):
    """Tear down any specific state."""
    assert module is not None


def mocked_fetch_public_keys_1(app):
    """Mock for the function fetch_public_key()."""
    return [{}]


def mocked_fetch_public_keys_2(app):
    """Mock for the function fetch_public_key()."""
    return [{"nothing": "nothing"}]


def mocked_fetch_public_keys_3(app):
    """Mock for the function fetch_public_key()."""
    return [{"keyid": 666, "key": PUBLIC_KEY}]


def mocked_fetch_public_keys_4(app):
    """Mock for the function fetch_public_key()."""
    return [{"keyid": 667, "key": WRONG_PUBLIC_KEY}]


def mocked_get_audiences():
    """Mock for the function get_audiences()."""
    return []


def mocked_get_audiences_2():
    """Mock for the function get_audiences()."""
    return ["audience1", "audience2"]


def mocked_get_audiences_3():
    """Mock for the function get_audiences()."""
    return ["fabric8-online-platform", "openshiftio-public"]


def mocked_requests_get(endpoint, timeout=2):
    """Mock HTTP request."""
    class MockResponse:
        def __init__(self, status_code):
            self.status_code = 200
            self.text = "Testing text"

        def status_code(self):
            return self.status_code

        def text(self):
            return self.text

        def json(self):
            return json.loads('{"keys" : [{"key": "value1","keyid": "thekey_id"}]}')

    assert endpoint is not None
    assert timeout >= 0
    return MockResponse([{"key": "value1", "keyid": "thekey_id"}])


def mocked_requests(endpoint, json, timeout=2):
    """Mock HTTP request."""
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.text = "Testing text"

        def json(self):
            return self.json_data

        def status_code(self):
            return self.status_code

        def text(self):
            return self.text

    assert endpoint is not None
    assert timeout >= 0
    return MockResponse({"access_token": "value1"}, 200)


def get_current_app():
    """Get flask app instance."""
    return APP


def mocked_get_token_from_auth_header():
    """Mock that returns token."""
    payload = {
        'preferred_username': 'pllm',
        'some': 'payload',
        'email_verified': '1',
        'aud': 'openshiftio-public',
        'sub': 'pllm'
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")


def mocked_get_threescale_account_secret_header_none():
    """Mock that returns the 3scale secret as None."""
    return None


def mocked_get_threescale_account_secret_header():
    """Mock that returns the secret."""
    return "secret"


def mocked_get_token_from_auth_header_service_account():
    """Mock that returns token."""
    payload = {
        'preferred_username': 'pllm',
        'sub': 'pllm',
        'some': 'payload',
        'email_verified': '1'
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_1, create=True)
def test_decode_token_invalid_input_1(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    assert decode_user_token(APP, None) is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_1, create=True)
def test_decode_token_invalid_input_2(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    assert decode_user_token(APP, "Foobar") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_1, create=True)
def test_decode_token_invalid_input_3(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    assert decode_user_token(APP, "Bearer ") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_2, create=True)
def test_decode_token_invalid_input_4(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    assert decode_user_token(APP, "Bearer ") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_2, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_2, create=True)
def test_decode_token_invalid_input_5(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    assert decode_user_token(APP, "Bearer something") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_decode_token_invalid_input_6(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_user_token(APP, token) is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_decode_token_invalid_input_7(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '0'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_user_token(APP, token) is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_decode_token_valid_input(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '1',
        'aud': 'openshiftio-public',
        'preferred_username': 'pllm',
        'sub': 'pllm',
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_user_token(APP, token) is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_4, create=True)
def test_decode_token_invalid_key_input(_mocked_fetch_public_key, _mocked_get_audiences):
    """Test the handling wrong public key tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '1'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_user_token(APP, token) is None


@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_service_token_valid_input(_mocked_fetch_public_key):
    """Test the handling JWT tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '1'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_service_token(APP, token) is not None


@patch("requests.post",
       side_effect=mocked_requests, create=True)
def test_init_service_account_token(mocked_requests):
    """Test the handling of service account JWT tokens."""
    assert init_service_account_token(create_app()) is not None


@patch("requests.get",
       side_effect=mocked_requests_get, create=True)
@patch.dict(os.environ, {"OSIO_AUTH_URL": "http://auth.openshift.io"})
def test_fetch_public_keys(mocked_requests_get):
    """Test fetching of public keys."""
    assert fetch_public_keys(APP) is not None


@patch.dict(os.environ, {"THREESCALE_ACCOUNT_SECRET": "secret"})
@patch("fabric8a_auth.auth.get_threescale_account_secret_header",
       side_effect=mocked_get_threescale_account_secret_header, create=True)
def test_login_required_valid_secret(_mocked_get_threescale_account_secret_header):
    """Test login required wrapper for user using 3scale secret."""
    @login_required
    def testing_method():
        return True

    result = testing_method()
    assert result is not None


@patch.dict(os.environ, {"THREESCALE_ACCOUNT_SECRET": "secret1"})
@patch("fabric8a_auth.auth.get_threescale_account_secret_header",
       side_effect=mocked_get_threescale_account_secret_header, create=True)
def test_login_required_invalid_secret(_mocked_get_threescale_account_secret_header):
    """Test login required wrapper for user using 3scale secret."""
    @login_required
    def testing_method():
        return True

    with pytest.raises(AuthError):
        result = testing_method()
        assert result is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
@patch("fabric8a_auth.auth.get_token_from_auth_header",
       side_effect=mocked_get_token_from_auth_header, create=True)
@patch.dict(os.environ, {"THREESCALE_ACCOUNT_SECRET": ""})
@patch("fabric8a_auth.auth.get_threescale_account_secret_header",
       side_effect=mocked_get_threescale_account_secret_header_none, create=True)
def test_user_wrapper(_mocked_fetch_public_key, _mocked_get_audiences,
                      _mocked_get_token_from_auth_header,
                      _mocked_get_threescale_account_secret_header_none):
    """Test login required wrapper for user."""
    @login_required
    def testing_method():
        return True

    result = testing_method()
    assert result is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_4, create=True)
@patch("fabric8a_auth.auth.get_token_from_auth_header",
       side_effect=mocked_get_token_from_auth_header, create=True)
@patch.dict(os.environ, {"THREESCALE_ACCOUNT_SECRET": ""})
@patch("fabric8a_auth.auth.get_threescale_account_secret_header",
       side_effect=mocked_get_threescale_account_secret_header_none, create=True)
def test_user_wrapper_wrong_key(_mocked_fetch_public_key, _mocked_get_audiences,
                                _mocked_get_token_from_auth_header,
                                _mocked_get_threescale_account_secret_header_none):
    """Test login required wrapper for user."""
    @login_required
    def testing_method():
        return True

    with pytest.raises(AuthError):
        result = testing_method()
        assert result is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
@patch("fabric8a_auth.auth.get_token_from_auth_header",
       side_effect=mocked_get_token_from_auth_header_service_account, create=True)
def test_service_account_wrapper(_mocked_fetch_public_key, _mocked_get_audiences,
                                 _mocked_get_token_from_auth_header_service_account):
    """Test login required wrapper for service account."""
    @service_token_required
    def testing_method():
        return True

    result = testing_method()
    assert result is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_4, create=True)
@patch("fabric8a_auth.auth.get_token_from_auth_header",
       side_effect=mocked_get_token_from_auth_header_service_account, create=True)
def test_service_account_wrapper_wrong_key(_mocked_fetch_public_key, mocked_get_audiences,
                                           _mocked_get_token_from_auth_header_service_account):
    """Test login required wrapper for service account."""
    @service_token_required
    def testing_method():
        return True

    with pytest.raises(AuthError):
        result = testing_method()
        assert result is not None


if __name__ == '__main__':
    test_decode_token_invalid_input_1()
    test_decode_token_invalid_input_2()
    test_decode_token_invalid_input_3()
    test_decode_token_invalid_input_4()
    test_decode_token_invalid_input_5()
