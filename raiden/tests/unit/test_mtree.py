from collections import OrderedDict

import pytest

from raiden.exceptions import HashLengthNot32
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.merkle_tree import MERKLEROOT, compute_layers
from raiden.transfer.state import MerkleTreeState
from raiden.utils import sha3
from raiden_contracts.tests.constants import LOCKSROOT_OF_NO_LOCKS


def test_empty():
    locks = OrderedDict()
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


def test_compute_layers_single_entry():
    hash_0 = sha3(b"x")
    layers = compute_layers([hash_0])
    assert layers[MERKLEROOT][0] == hash_0

    tree = MerkleTreeState(layers)
    assert compute_locksroot(tree) == hash_0
