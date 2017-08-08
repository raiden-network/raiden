# -*- coding: utf-8 -*-
import pytest

from raiden.messages import EMPTY_MERKLE_ROOT
from raiden.exceptions import HashLengthNot32
from raiden.mtree import Merkletree, check_proof
from raiden.utils import sha3


def test_empty():
    assert Merkletree([]).merkleroot == EMPTY_MERKLE_ROOT


def test_non_hash():
    with pytest.raises(HashLengthNot32):
        Merkletree(['not32bytes', 'neither'])

    with pytest.raises(HashLengthNot32):
        Merkletree(['']).merkleroot


def test_single():
    hash_0 = sha3('x')
    assert Merkletree([hash_0]).merkleroot == hash_0


def test_duplicates():
    hash_0 = sha3('x')
    hash_1 = sha3('y')

    with pytest.raises(ValueError):
        Merkletree([hash_0, hash_0])

    with pytest.raises(ValueError):
        Merkletree([hash_0, hash_1, hash_0])


def test_one():
    hash_0 = 'a' * 32

    leaves = [hash_0]
    tree = Merkletree(leaves)
    merkle_root = tree.merkleroot
    merkle_proof = tree.make_proof(hash_0)

    assert merkle_proof == []
    assert merkle_root == hash_0
    assert check_proof(merkle_proof, merkle_root, hash_0) is True


def test_two():
    hash_0 = 'a' * 32
    hash_1 = 'b' * 32

    leaves = [hash_0, hash_1]

    tree = Merkletree(leaves)
    merkle_root = tree.merkleroot
    merkle_proof0 = tree.make_proof(hash_0)

    assert merkle_proof0 == [hash_1]
    assert merkle_root == sha3(hash_0 + hash_1)
    assert check_proof(merkle_proof0, merkle_root, hash_0)

    merkle_proof1 = tree.make_proof(hash_1)

    assert merkle_proof1 == [hash_0]
    assert merkle_root == sha3(hash_0 + hash_1)
    assert check_proof(merkle_proof1, merkle_root, hash_1)


def test_three():
    def sort_join(first, second):
        return ''.join(sorted([first, second]))

    hash_0 = 'a' * 32
    hash_1 = 'b' * 32
    hash_2 = 'c' * 32

    leaves = [hash_0, hash_1, hash_2]
    tree = Merkletree(leaves)
    merkle_root = tree.merkleroot

    hash_01 = (
        b'me\xef\x9c\xa9=5\x16\xa4\xd3\x8a\xb7\xd9\x89\xc2\xb5\x00'
        b'\xe2\xfc\x89\xcc\xdc\xf8x\xf9\xc4m\xaa\xf6\xad\r['
    )
    assert sha3(hash_0 + hash_1) == hash_01
    calculated_root = sha3(hash_2 + hash_01)

    merkle_proof0 = tree.make_proof(hash_0)
    assert merkle_proof0 == [hash_1, hash_2]
    assert merkle_root == calculated_root
    assert check_proof(merkle_proof0, merkle_root, hash_0)

    merkle_proof1 = tree.make_proof(hash_1)
    assert merkle_proof1 == [hash_0, hash_2]
    assert merkle_root == calculated_root
    assert check_proof(merkle_proof1, merkle_root, hash_1)

    # with an odd number of values, the last value wont appear by itself in the
    # proof since it isn't hashed with another value
    merkle_proof2 = tree.make_proof(hash_2)
    assert merkle_proof2 == [sha3(hash_0 + hash_1)]
    assert merkle_root == calculated_root
    assert check_proof(merkle_proof2, merkle_root, hash_2)


def test_many(tree_up_to=10):
    for number_of_leaves in range(tree_up_to):
        leaves = [
            sha3(str(value))
            for value in range(number_of_leaves)
        ]
        tree = Merkletree(leaves)
        merkleroot = tree.merkleroot

        for value in leaves:
            merkle_proof = tree.make_proof(value)
            assert check_proof(merkle_proof, merkleroot, value)

        assert merkleroot == Merkletree(reversed(leaves)).merkleroot
