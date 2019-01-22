"""Unit tests for various utility functions."""

from fabric8a_auth.auth import is_authentication_disabled, get_audiences
import os


def test_is_authentication_disabled_negative_test():
    """Test the function is_authentication_disabled()."""
    os.environ['DISABLE_AUTHENTICATION'] = ''
    assert not is_authentication_disabled()

    os.environ['DISABLE_AUTHENTICATION'] = '0'
    assert not is_authentication_disabled()

    os.environ['DISABLE_AUTHENTICATION'] = 'false'
    assert not is_authentication_disabled()

    os.environ['DISABLE_AUTHENTICATION'] = 'False'
    assert not is_authentication_disabled()

    os.environ['DISABLE_AUTHENTICATION'] = 'FALSE'
    assert not is_authentication_disabled()


def test_is_authentication_disabled_positive_test():
    """Test the function is_authentication_disabled()."""
    os.environ['DISABLE_AUTHENTICATION'] = '1'
    assert is_authentication_disabled()

    os.environ['DISABLE_AUTHENTICATION'] = 'True'
    assert is_authentication_disabled()

    os.environ['DISABLE_AUTHENTICATION'] = 'true'
    assert is_authentication_disabled()

    os.environ['DISABLE_AUTHENTICATION'] = 'TRUE'
    assert is_authentication_disabled()


def test_get_audiences():
    """Test the function get_audiences()."""
    os.environ.unsetenv('FABRIC8_ANALYTICS_JWT_AUDIENCE')
    assert get_audiences() == ['']

    os.environ['FABRIC8_ANALYTICS_JWT_AUDIENCE'] = ''
    assert get_audiences() == ['']

    os.environ['FABRIC8_ANALYTICS_JWT_AUDIENCE'] = 'a'
    assert get_audiences() == ['a']

    os.environ['FABRIC8_ANALYTICS_JWT_AUDIENCE'] = 'a,b'
    assert get_audiences() == ['a', 'b']

    os.environ['FABRIC8_ANALYTICS_JWT_AUDIENCE'] = 'a,b,'
    assert get_audiences() == ['a', 'b', '']

    os.environ['FABRIC8_ANALYTICS_JWT_AUDIENCE'] = 'a,b,c'
    assert get_audiences() == ['a', 'b', 'c']


if __name__ == '__main__':
    test_is_authentication_disabled_negative_test()
    test_is_authentication_disabled_positive_test()
    test_get_audiences()
