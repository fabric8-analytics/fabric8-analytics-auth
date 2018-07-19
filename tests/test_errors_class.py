"""Unit tests for the errors module."""

import unittest
import pytest
import fabric8a_auth.errors


def test_http_error_attributes():
    """Test the basic behaviour of HTTPError class."""
    e = fabric8a_auth.errors.HTTPError(404, "Not found")
    assert e.status_code == 404
    assert e.error == "Not found"


def test_http_error_raise():
    """Test the basic behaviour of HTTPError class."""
    with pytest.raises(fabric8a_auth.errors.HTTPError) as e:
        raise fabric8a_auth.errors.HTTPError(404, "Not found")


def test_http_error_exception_handling():
    """Test the basic behaviour of HTTPError class."""
    try:
        raise fabric8a_auth.errors.HTTPError(404, "Not found")
    except fabric8a_auth.errors.HTTPError as e:
        print(e)


if __name__ == '__main__':
    test_http_error_attributes()
    test_http_error_raise()
    test_http_error_exception_handling()
