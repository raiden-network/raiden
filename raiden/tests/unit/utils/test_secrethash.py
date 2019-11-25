from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import Secret


def test_sha256_secrethash():
    assert sha256_secrethash(Secret(b"")) == (
        b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$"
        b"'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U"
    )

    assert sha256_secrethash(Secret(b"a")) == (
        b"\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc21\xb3\x9a#\xdcM"
        b"\xa7\x86\xef\xf8\x14|Nr\xb9\x80w\x85\xaf\xeeH\xbb"
    )
    secret = Secret(b"secretsecretsecretsecretsecretse")
    assert sha256_secrethash(secret) == (
        b'\xd4h:"\xc1\xce9\x82M\x93\x1e\xed\xc6\x8e\xa8\xfa'
        b"RY\xce\xb05(\xb1\xa2/pu\x86>\xf8\xba\xf0"
    )
