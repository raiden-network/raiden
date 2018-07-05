import pytest
from werkzeug.routing import ValidationError

from raiden.api.v1.encoding import decode_keccak


def test_decode_keccak():
    with pytest.raises(ValidationError):
        decode_keccak('abc')

    with pytest.raises(ValidationError):
        decode_keccak('0xxyz')

    valid_hash = '0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658'
    valid_bytes = (
        b'\x9c"\xff_!\xf0\xb8\x1b\x11>c\xf7\xdbm\xa9O\xed\xef'
        b'\x11\xb2\x11\x9b@\x88\xb8\x96d\xfb\x9a<\xb6X'
    )

    with pytest.raises(ValidationError):
        decode_keccak(valid_hash[:-1])

    assert decode_keccak(valid_hash) == valid_bytes
