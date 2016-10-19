# -*- coding: utf-8 -*-
import pytest

from raiden.mtree import merkleroot, check_proof, get_proof, NoHash32Error
from raiden.utils import keccak


def test_empy():
    assert merkleroot('') == ''


def test_multiple_empty():
    assert merkleroot(['', '']) == ''


def test_non_hash():
    with pytest.raises(NoHash32Error):
        merkleroot(['not32bytes', 'neither'])


def test_single():
    hash_0 = keccak('x')
    assert merkleroot([hash_0]) == hash_0


def test_duplicates():
    hash_0 = keccak('x')
    hash_1 = keccak('y')

    assert merkleroot([hash_0, hash_0]) == hash_0, 'duplicates should be removed'
    assert merkleroot([hash_0, hash_1, hash_0]) == merkleroot([hash_0, hash_1]), 'duplicates should be removed'


def test_one():
    hash_0 = 'a' * 32

    merkle_tree = [hash_0]
    merkle_proof = [hash_0]  # modified in place
    merkle_root = merkleroot(merkle_tree, merkle_proof)

    assert merkle_proof == []
    assert merkle_root == hash_0
    assert check_proof(merkle_proof, merkle_root, hash_0) is True


def test_two():
    hash_0 = 'a' * 32
    hash_1 = 'b' * 32

    merkle_tree = [hash_0, hash_1]

    merkle_proof = [hash_0]  # modified in place
    merkle_root = merkleroot(merkle_tree, merkle_proof)

    assert merkle_proof == [hash_1]
    assert merkle_root == keccak(hash_0 + hash_1)
    assert check_proof(merkle_proof, merkle_root, hash_0)

    merkle_proof = [hash_1]  # modified in place
    merkle_root = merkleroot(merkle_tree, merkle_proof)

    assert merkle_proof == [hash_0]
    assert merkle_root == keccak(hash_0 + hash_1)
    assert check_proof(merkle_proof, merkle_root, hash_1)


def test_three():
    def sort_join(first, second):
        return ''.join(sorted([first, second]))

    hash_0 = 'a' * 32
    hash_1 = 'b' * 32
    hash_2 = 'c' * 32

    merkle_tree = [hash_0, hash_1, hash_2]

    hash_01 = b'me\xef\x9c\xa9=5\x16\xa4\xd3\x8a\xb7\xd9\x89\xc2\xb5\x00\xe2\xfc\x89\xcc\xdc\xf8x\xf9\xc4m\xaa\xf6\xad\r['
    assert keccak(hash_0 + hash_1) == hash_01
    calculated_root = keccak(hash_2 + hash_01)

    merkle_proof = [hash_0]  # modified in place
    merkle_root = merkleroot(merkle_tree, merkle_proof)

    assert merkle_proof == [hash_1, hash_2]
    assert merkle_root == calculated_root
    assert check_proof(merkle_proof, merkle_root, hash_0)

    merkle_proof = [hash_1]  # modified in place
    merkle_root = merkleroot(merkle_tree, merkle_proof)

    assert merkle_proof == [hash_0, hash_2]
    assert merkle_root == calculated_root
    assert check_proof(merkle_proof, merkle_root, hash_1)

    merkle_proof = [hash_2]  # modified in place
    merkle_root = merkleroot(merkle_tree, merkle_proof)

    # with an odd number of values, the last value wont appear by itself in the
    # proof since it isn't hashed with another value
    assert merkle_proof == [keccak(hash_0 + hash_1)]
    assert merkle_root == calculated_root
    assert check_proof(merkle_proof, merkle_root, hash_2)


def test_get_proof():
    hash_0 = 'a' * 32
    hash_1 = 'b' * 32

    merkle_tree = [hash_0, hash_1]

    merkle_proof = [hash_0]  # modified in place
    merkle_root = merkleroot(merkle_tree, merkle_proof)
    assert check_proof(merkle_proof, merkle_root, hash_0)

    second_merkle_proof = get_proof(merkle_tree, hash_0, merkle_root)
    assert check_proof(second_merkle_proof, merkle_root, hash_0)
    assert merkle_proof == second_merkle_proof


def test_many(tree_up_to=10):
    for number_of_leaves in range(tree_up_to):
        merkle_tree = [
            keccak(str(value))
            for value in range(number_of_leaves)
        ]

        for value in merkle_tree:
            merkle_proof = [value]
            merkle_root = merkleroot(merkle_tree, merkle_proof)
            second_proof = get_proof(merkle_tree, value, merkle_root)

            assert check_proof(merkle_proof, merkle_root, value) is True
            assert check_proof(second_proof, merkle_root, value) is True

        assert merkleroot(merkle_tree) == merkleroot(reversed(merkle_tree))
