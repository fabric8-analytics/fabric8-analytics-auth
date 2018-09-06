"""Unit tests for the errors module."""

import pytest
import fabric8a_auth.errors


def test_http_error_attributes():
    """Test the basic behaviour of AuthError class."""
    e = fabric8a_auth.errors.AuthError(404, "Not found")
    assert e.status_code == 404
    assert e.error == "Not found"


def test_http_error_raise():
    """Test the basic behaviour of AuthError class."""
    with pytest.raises(fabric8a_auth.errors.AuthError) as e:
        raise fabric8a_auth.errors.AuthError(404, "Not found")


def test_http_error_exception_handling():
    """Test the basic behaviour of AuthError class."""
    try:
        raise fabric8a_auth.errors.AuthError(404, "Not found")
    except fabric8a_auth.errors.AuthError as e:
        print(e)


if __name__ == '__main__':
    test_http_error_attributes()
    test_http_error_raise()
    test_http_error_exception_handling()
