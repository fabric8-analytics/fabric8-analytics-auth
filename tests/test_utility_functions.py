"""Unit tests for various utility functions."""

import pytest
import fabric8a_auth.auth import is_authentication_disabled
import os


def test_is_authentication_disabled_negative_test():
    """Test the function is_authentication_disabled()."""
    os.environ.set('DISABLE_AUTHENTICATION', '')
    assert not is_authentication_disabled()

    os.environ.set('DISABLE_AUTHENTICATION', '0')
    assert not is_authentication_disabled()

    os.environ.set('DISABLE_AUTHENTICATION', 'false')
    assert not is_authentication_disabled()

    os.environ.set('DISABLE_AUTHENTICATION', 'False')
    assert not is_authentication_disabled()

    os.environ.set('DISABLE_AUTHENTICATION', 'FALSE')
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
if __name__ == '__main__':
    test_is_authentication_disabled_negative_test()
    test_is_authentication_disabled_positive_test()
