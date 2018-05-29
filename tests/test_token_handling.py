"""Unit tests for token handling functions."""

import unittest
from unittest.mock import *

from f8a_auth import *


class _response:

    def __init__(self, status_code, text, ok):
        self.status_code = status_code
        self.text = text
        self.ok = ok


def test_decode_token():
    assert decode_token(None) == {}


if __name__ == '__main__':
    test_decode_token()
