import pytest

from raiden.constants import EMPTY_MERKLE_ROOT
from raiden.exceptions import HashLengthNot32
from raiden.transfer.merkle_tree import MERKLEROOT, compute_layers, merkleroot
from raiden.transfer.state import MerkleTreeState
from raiden.utils import sha3


def test_empty():
    tree = MerkleTreeState([[EMPTY_MERKLE_ROOT]])
    assert merkleroot(tree) == EMPTY_MERKLE_ROOT


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
    assert merkleroot(tree) == hash_0
