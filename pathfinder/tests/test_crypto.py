# -*- coding: utf-8 -*-
import pytest
from eth_utils import keccak

from pathfinder.config import EMPTY_MERKLE_ROOT
from pathfinder.utils.crypto import compute_merkle_tree, get_merkle_root


def test_compute_merkle_tree_invalid_length():
    with pytest.raises(ValueError):
        compute_merkle_tree([b'not32bytes', b'neither'])

    with pytest.raises(ValueError):
        compute_merkle_tree([b''])


def test_compute_merkle_tree_duplicated():
    hash_0 = keccak(b'x')
    hash_1 = keccak(b'y')

    with pytest.raises(ValueError):
        compute_merkle_tree([hash_0, hash_0])

    with pytest.raises(ValueError):
        compute_merkle_tree([hash_0, hash_1, hash_0])


def test_compute_merkle_tree_no_entry():
    merkle_tree = compute_merkle_tree([])

    assert merkle_tree.layers[-1][0] == EMPTY_MERKLE_ROOT
    assert get_merkle_root(merkle_tree) == EMPTY_MERKLE_ROOT


def test_compute_merkle_tree_single_entry():
    hash_0 = keccak(b'x')
    merkle_tree = compute_merkle_tree([hash_0])

    assert merkle_tree.layers[-1][0] == hash_0
    assert get_merkle_root(merkle_tree) == hash_0


def test_get_merkle_root_one():
    hash_0 = b'a' * 32

    leaves = [hash_0]
    merkle_tree = compute_merkle_tree(leaves)
    root = get_merkle_root(merkle_tree)

    assert root == hash_0


def test_get_merkle_root_two():
    hash_0 = b'a' * 32
    hash_1 = b'b' * 32

    leaves = [hash_0, hash_1]
    merkle_tree = compute_merkle_tree(leaves)
    root = get_merkle_root(merkle_tree)

    assert root == keccak(hash_0 + hash_1)


def test_three():
    hash_0 = b'a' * 32
    hash_1 = b'b' * 32
    hash_2 = b'c' * 32

    leaves = [hash_0, hash_1, hash_2]
    merkle_tree = compute_merkle_tree(leaves)
    root = get_merkle_root(merkle_tree)

    hash_01 = (
        b'me\xef\x9c\xa9=5\x16\xa4\xd3\x8a\xb7\xd9\x89\xc2\xb5\x00'
        b'\xe2\xfc\x89\xcc\xdc\xf8x\xf9\xc4m\xaa\xf6\xad\r['
    )
    assert keccak(hash_0 + hash_1) == hash_01
    calculated_root = keccak(hash_2 + hash_01)

    assert root == calculated_root
