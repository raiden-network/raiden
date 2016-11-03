# -*- coding: utf-8 -*-
from __future__ import division

from ethereum.utils import encode_hex

from raiden.utils import keccak


def hash_pair(first, second):
    if second is None:
        return first
    if first is None:
        return second
    if first > second:
        return keccak(second + first)
    return keccak(first + second)


class NoHash32Error(Exception):
    pass


def iterate_pairwise(elements):
    """ iterate pairwise over the given list, i.e. the functions yields
    a list of consecutive 2-tuples. The second element in the last
    tuple yielded is None iff the len of the given list is odd """
    for i in range(len(elements) // 2):
        yield elements[i * 2], elements[i * 2 + 1]
    if len(elements) % 2:
        yield elements[-1], None


def merkletreelayers(elements):
    """ computes the layers of the merkletree. First layer is the list
    of elements and the last layer is a list with a single entry, the
    merkleroot """

    yield elements
    if len(elements) == 0:
        yield [""]
    while len(elements) > 1:
        elements = [hash_pair(a, b) for a, b in iterate_pairwise(elements)]
        yield elements


def merkleproof_from_layers(layers, idx):
    proof = []
    for layer in layers:
        pair_idx = idx - 1 if idx % 2 else idx + 1
        if pair_idx < len(layer):
            proof.append(layer[pair_idx])
        idx = idx // 2
    return proof


class Merkletree(object):
    def __init__(self, elements):
        self._layers = list(merkletreelayers(build_lst(elements)))

    @property
    def merkleroot(self):
        return self._layers[-1][0]

    def make_proof(self, element):
        """ The proof contains all elements between `element` and `root`.
            If on all of [element] + proof is recursively hash_pair applied one
            gets the root.
        """
        return merkleproof_from_layers(self._layers, self._layers[0].index(element))


def merkleroot(elements):
    """
    Args:
        elements (List[str]): List of hashes that make the merkletree.

    Returns:
        str: The root element of the merkle tree.
    """
    return Merkletree(elements).merkleroot



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
    tree = Merkletree(lst)

    root_hash = tree.merkleroot
    if root and root != root_hash:
        raise ValueError('root hashes did not match {} {}'.format(
            encode_hex(root_hash),
            encode_hex(root)
        ))

    return tree.make_proof(proof_for)
