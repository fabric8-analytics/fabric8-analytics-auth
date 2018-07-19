"""Unit tests for the authorization module."""

import unittest
from fabric8a_auth import User


def test_user_class():
    """Test the basic behaviour of User class."""
    email = "tester@foo.bar.baz"
    user = User(email)
    # just dummy check ATM as the class is pretty simple
    assert email == user.email


if __name__ == '__main__':
    test_user_class()
