"""Unit tests for token handling functions."""

from unittest.mock import *

import jwt
import pytest
from flask import Flask

from fabric8a_auth.auth import decode_user_token, decode_service_token, init_service_account_token


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
    pass


def mocked_fetch_public_keys_1(app):
    """Mock for the function fetch_public_key()."""
    return None


def mocked_fetch_public_keys_2(app):
    """Mock for the function fetch_public_key()."""
    return "nothing"


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


def mocked_requests_post_1(endpoint, json):
    """Moc http request."""
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

        def status_code(self):
            return self.status_code

    return MockResponse({"access_token": "value1"}, 200)


def get_current_app():
    """Get flask app instance."""
    return APP


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_1, create=True)
def test_decode_token_invalid_input_1(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    with pytest.raises(jwt.exceptions.InvalidTokenError):
        assert decode_user_token(APP, None) == {}


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_1, create=True)
def test_decode_token_invalid_input_2(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    with pytest.raises(Exception):
        assert decode_user_token(APP, "Foobar") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_1, create=True)
def test_decode_token_invalid_input_3(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    with pytest.raises(Exception):
        assert decode_user_token(APP, "Bearer ") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_2, create=True)
def test_decode_token_invalid_input_4(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    with pytest.raises(Exception):
        assert decode_user_token(APP, "Bearer ") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_2, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_2, create=True)
def test_decode_token_invalid_input_5(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    with pytest.raises(Exception):
        assert decode_user_token(APP, "Bearer something") is None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_decode_token_invalid_input_6(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    with pytest.raises(jwt.InvalidTokenError):
        assert decode_user_token(APP, token) is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_decode_token_invalid_input_7(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '0'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    with pytest.raises(jwt.InvalidTokenError):
        assert decode_user_token(APP, token) is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_decode_token_valid_input(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '1',
        'aud': 'openshiftio-public'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_user_token(APP, token) is not None


@patch("fabric8a_auth.auth.get_audiences",
       side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_4, create=True)
def test_decode_token_invalid_key_input(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong public key tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '1'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    with pytest.raises(jwt.InvalidTokenError):
        assert decode_user_token(APP, token) is not None


@patch("fabric8a_auth.auth.fetch_public_keys",
       side_effect=mocked_fetch_public_keys_3, create=True)
def test_service_token_valid_input(mocked_fetch_public_key):
    """Test the handling JWT tokens."""
    payload = {
        'some': 'payload',
        'email_verified': '1'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_service_token(APP, token) is not None


@patch("requests.post",
       side_effect=mocked_requests_post_1, create=True)
def test_init_service_account_token(mocked_requests_post_1):
    """Test the handling JWT tokens."""
    assert init_service_account_token(create_app()) is not None


if __name__ == '__main__':
    test_decode_token_invalid_input_1()
    test_decode_token_invalid_input_2()
    test_decode_token_invalid_input_3()
    test_decode_token_invalid_input_4()
    test_decode_token_invalid_input_5()
