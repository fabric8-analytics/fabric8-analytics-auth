"""Unit tests for the errors module."""

import pytest
import fabric8a_auth.errors


def test_auth_error_attributes():
    """Test the basic behaviour of AuthError class."""
    e = fabric8a_auth.errors.AuthError(404, "Not found")
    assert e.status_code == 404
    assert e.error == "Not found"


def test_auth_error_raise():
    """Test the basic behaviour of AuthError class."""
    with pytest.raises(fabric8a_auth.errors.AuthError):
        raise fabric8a_auth.errors.AuthError(404, "Not found")


def test_auth_error_exception_handling():
    """Test the basic behaviour of AuthError class."""
    try:
        raise fabric8a_auth.errors.AuthError(404, "Not found")
    except fabric8a_auth.errors.AuthError as e:
        print(e)


def test_auth_error_repr_method():
    """Test the basic behaviour of AuthError class: the __repr__ method."""
    e = fabric8a_auth.errors.AuthError(200, "Ok")
    assert e.__repr__() == "AuthError(status_code=200,error=Ok)"
    e = fabric8a_auth.errors.AuthError(404, "Not found")
    assert e.__repr__() == "AuthError(status_code=404,error=Not found)"


def test_auth_error_str_method():
    """Test the basic behaviour of AuthError class: the __str__ method."""
    e = fabric8a_auth.errors.AuthError(200, "Ok")
    assert e.__str__() == "AuthError(200): Ok"
    e = fabric8a_auth.errors.AuthError(404, "Not found")
    assert e.__str__() == "AuthError(404): Not found"


if __name__ == '__main__':
    test_auth_error_attributes()
    test_auth_error_raise()
    test_auth_error_exception_handling()
    test_auth_error_repr_method()
    test_auth_error_str_method()
