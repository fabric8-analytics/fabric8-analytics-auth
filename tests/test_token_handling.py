"""Unit tests for token handling functions."""

from unittest.mock import *

import jwt
import pytest
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm

from fabric8a_auth.fabric8a_auth import decode_user_token


def setup_module(module):
    """Perform setup of any state specific to the execution of the given module."""
    global PRIVATE_KEY
    global PUBLIC_KEY

    # private and public key used in tests
    with open("private_key.pem") as fin:
        PRIVATE_KEY = fin.read()

    with open("public_key.pem") as fin:
        PUBLIC_KEY = fin.read()

    # just to make sure the following statement does not raise an exception
    try:
        jwt.unregister_algorithm('RS256')
    except KeyError:
        pass

    # make sure the RS256 algorithm is initialized
    jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))


def teardown_module(module):
    """Tear down any specific state."""
    pass


def mocked_fetch_public_key_1(app):
    """Mock for the function fetch_public_key()."""
    return None


def mocked_fetch_public_key_2(app):
    """Mock for the function fetch_public_key()."""
    return "nothing"


def mocked_fetch_public_key_3(app):
    """Mock for the function fetch_public_key()."""
    return PUBLIC_KEY


def mocked_get_audiences():
    """Mock for the function get_audiences()."""
    return []


def mocked_get_audiences_2():
    """Mock for the function get_audiences()."""
    return ["audience1", "audience2"]


def mocked_get_audiences_3():
    """Mock for the function get_audiences()."""
    return ["foo:bar", ]


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_1, create=True)
def test_decode_token_invalid_input_1(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    assert decode_user_token(None) == {}


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_1, create=True)
def test_decode_token_invalid_input_2(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    with pytest.raises(Exception):
        assert decode_user_token("Foobar") is None


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_1, create=True)
def test_decode_token_invalid_input_3(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    with pytest.raises(Exception):
        assert decode_user_token("Bearer ") is None


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_2, create=True)
def test_decode_token_invalid_input_4(mocked_fetch_public_key, mocked_get_audiences):
    """Test the invalid input handling during token decoding."""
    with pytest.raises(Exception):
        assert decode_user_token("Bearer ") is None


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences_2, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_2, create=True)
def test_decode_token_invalid_input_5(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    with pytest.raises(Exception):
        assert decode_user_token("Bearer something") is None


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_3, create=True)
def test_decode_token_invalid_input_6(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
        'aud': 'foo:bar'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    with pytest.raises(jwt.InvalidIssuerError):
        assert decode_user_token(token) is not None


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_3, create=True)
def test_decode_token_invalid_input_7(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
        'aud': 'foo:bar',
        'email_verified': '0'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    with pytest.raises(jwt.InvalidIssuerError):
        assert decode_user_token(token) is not None


@patch("fabric8a_auth.get_audiences", side_effect=mocked_get_audiences_3, create=True)
@patch("fabric8a_auth.fetch_public_key", side_effect=mocked_fetch_public_key_3, create=True)
def test_decode_token_valid_input(mocked_fetch_public_key, mocked_get_audiences):
    """Test the handling wrong JWT tokens."""
    payload = {
        'some': 'payload',
        'aud': 'foo:bar',
        'email_verified': '1'
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256').decode("utf-8")
    assert decode_user_token(token) is not None


if __name__ == '__main__':
    test_decode_token_invalid_input_1()
    test_decode_token_invalid_input_2()
    test_decode_token_invalid_input_3()
    test_decode_token_invalid_input_4()
    test_decode_token_invalid_input_5()
