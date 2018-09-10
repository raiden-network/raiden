import pytest

from raiden.exceptions import HashLengthNot32
from raiden.transfer.merkle_tree import (
    MERKLEROOT,
    compute_layers,
    compute_merkleproof_for,
    merkleroot,
    validate_proof,
)
from raiden.transfer.state import EMPTY_MERKLE_ROOT, MerkleTreeState
from raiden.utils import sha3


def sort_join(first, second):
    return ''.join(sorted([first, second]))


def test_empty():
    tree = MerkleTreeState([[EMPTY_MERKLE_ROOT]])
    assert merkleroot(tree) == EMPTY_MERKLE_ROOT


def test_compute_layers_empty():
    with pytest.raises(AssertionError):
        compute_layers([])


def test_compute_layers_invalid_length():
    with pytest.raises(HashLengthNot32):
        compute_layers([b'not32bytes', b'neither'])

    with pytest.raises(HashLengthNot32):
        compute_layers([b''])


def test_compute_layers_duplicated():
    hash_0 = sha3(b'x')
    hash_1 = sha3(b'y')

    with pytest.raises(ValueError):
        compute_layers([hash_0, hash_0])

    with pytest.raises(ValueError):
        compute_layers([hash_0, hash_1, hash_0])


def test_compute_layers_single_entry():
    hash_0 = sha3(b'x')
    layers = compute_layers([hash_0])
    assert layers[MERKLEROOT][0] == hash_0

    tree = MerkleTreeState(layers)
    assert merkleroot(tree) == hash_0


def test_one():
    hash_0 = b'a' * 32

    leaves = [hash_0]
    layers = compute_layers(leaves)
    tree = MerkleTreeState(layers)
    root = merkleroot(tree)
    proof = compute_merkleproof_for(tree, hash_0)

    assert proof == []
    assert root == hash_0
    assert validate_proof(proof, root, hash_0) is True


def test_two():
    hash_0 = b'a' * 32
    hash_1 = b'b' * 32

    leaves = [hash_0, hash_1]
    layers = compute_layers(leaves)
    tree = MerkleTreeState(layers)
    root = merkleroot(tree)
    proof0 = compute_merkleproof_for(tree, hash_0)
    proof1 = compute_merkleproof_for(tree, hash_1)

    assert proof0 == [hash_1]
    assert root == sha3(hash_0 + hash_1)
    assert validate_proof(proof0, root, hash_0)

    assert proof1 == [hash_0]
    assert root == sha3(hash_0 + hash_1)
    assert validate_proof(proof1, root, hash_1)


def test_three():
    hash_0 = b'a' * 32
    hash_1 = b'b' * 32
    hash_2 = b'c' * 32

    leaves = [hash_0, hash_1, hash_2]
    layers = compute_layers(leaves)
    tree = MerkleTreeState(layers)
    root = merkleroot(tree)

    hash_01 = (
        b'me\xef\x9c\xa9=5\x16\xa4\xd3\x8a\xb7\xd9\x89\xc2\xb5\x00'
        b'\xe2\xfc\x89\xcc\xdc\xf8x\xf9\xc4m\xaa\xf6\xad\r['
    )
    assert sha3(hash_0 + hash_1) == hash_01
    calculated_root = sha3(hash_2 + hash_01)

    proof0 = compute_merkleproof_for(tree, hash_0)
    proof1 = compute_merkleproof_for(tree, hash_1)
    proof2 = compute_merkleproof_for(tree, hash_2)

    assert proof0 == [hash_1, hash_2]
    assert root == calculated_root
    assert validate_proof(proof0, root, hash_0)

    assert proof1 == [hash_0, hash_2]
    assert root == calculated_root
    assert validate_proof(proof1, root, hash_1)

    # with an odd number of values, the last value wont appear by itself in the
    # proof since it isn't hashed with another value
    assert proof2 == [sha3(hash_0 + hash_1)]
    assert root == calculated_root
    assert validate_proof(proof2, root, hash_2)


def test_many(tree_up_to=10):
    for number_of_leaves in range(1, tree_up_to):  # skipping the empty tree

        leaves = [
            sha3(str(value).encode())
            for value in range(number_of_leaves)
        ]

        layers = compute_layers(leaves)
        tree = MerkleTreeState(layers)
        root = merkleroot(tree)

        for value in leaves:
            proof = compute_merkleproof_for(tree, value)
            assert validate_proof(proof, root, value)

        reversed_tree = MerkleTreeState(compute_layers(reversed(leaves)))
        assert root == merkleroot(reversed_tree)
