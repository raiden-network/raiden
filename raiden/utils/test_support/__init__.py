# This package contains utilities that are shared between `pytest` and `smoketest`.
import random
import string

from raiden.utils.signer import LocalSigner, Signer


def make_signer() -> Signer:
    privatekey = make_privatekey_bin()
    return LocalSigner(privatekey)


def make_privatekey_bin() -> bytes:
    return make_bytes(32)


def make_bytes(length: int) -> bytes:
    return bytes("".join(random.choice(string.printable) for _ in range(length)), encoding="utf-8")
