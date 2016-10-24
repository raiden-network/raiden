# -*- coding: utf-8 -*-
from __future__ import division

from ethereum.utils import encode_hex

from raiden.utils import keccak


def hash_pair(first, second):
    if first > second:
        return keccak(second + first)
    return keccak(first + second)


class NoHash32Error(Exception):
    pass


def _merkleroot(elements, proof=None):
    proof = proof or [None]
    searching = proof.pop()
    assert searching is None or searching in elements
    out = []
    for i in range(len(elements) // 2):
        first = elements[i * 2]
        second = elements[i * 2 + 1]

        hash_ = hash_pair(first, second)
        if first == searching:
            proof.extend((second, hash_))
        elif second == searching:
            proof.extend((first, hash_))
        out.append(hash_)

    if len(elements) % 2:
        hash_ = elements[-1]
        out.append(hash_)
        if hash_ == searching:
            proof.append(hash_)

    if len(out) > 1:
        return _merkleroot(out, proof)

    if searching:
        proof.pop()  # pop root
    return out[0]


def merkleroot(elements, proof=None):
    """
    Args:
        elements (List[str]): List of hashes that make the merkletree.
        proof (list): Empty or list with a single element for which a proof shall be
            built. The resulting proof will be in proof, i.e. the list
            is modified in place.

            The proof contains all elements between `element` and `root`.
            If on all of [element] + proof is recursively hash_pair applied one
            gets the root.

    Returns:
        str: The root element of the merkle tree.
    """
    elements = build_lst(elements)
    if not elements:
        return ''
    return _merkleroot(elements, proof=proof)


def build_lst(elements):
    result = list()

    for item in set(elements):
        if item:
            if len(item) != 32:
                raise NoHash32Error()

            result.append(item)

    result.sort()
    return result


def check_proof(proof, root, hash_):
    for x in proof:
        hash_ = hash_pair(hash_, x)

    return hash_ == root


def get_proof(lst, proof_for, root=None):
    proof = [proof_for]
    root_hash = merkleroot(lst, proof)

    if root and root != root_hash:
        raise ValueError('root hashes did not match {} {}'.format(
            encode_hex(root_hash),
            encode_hex(root)
        ))

    return proof
