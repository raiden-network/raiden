import pytest

from raiden.exceptions import HashLengthNot32
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.merkle_tree import compute_layers
from raiden.utils import sha3
from raiden_contracts.tests.utils import LOCKSROOT_OF_NO_LOCKS


def test_empty():
    locks = dict()
    assert compute_locksroot(locks) == LOCKSROOT_OF_NO_LOCKS


def test_compute_layers_empty():
    with pytest.raises(AssertionError):
        compute_layers([])


def test_compute_layers_invalid_length():
    with pytest.raises(HashLengthNot32):
        compute_layers([b"not32bytes", b"neither"])

    with pytest.raises(HashLengthNot32):
        compute_layers([b""])


def test_compute_layers_duplicated():
    hash_0 = sha3(b"x")
    hash_1 = sha3(b"y")

    with pytest.raises(ValueError):
        compute_layers([hash_0, hash_0])

    with pytest.raises(ValueError):
        compute_layers([hash_0, hash_1, hash_0])
