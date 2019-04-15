# the layers grow from the leaves to the root
from typing import TYPE_CHECKING

from raiden.exceptions import HashLengthNot32
from raiden.utils import sha3, split_in_pairs
from raiden.utils.typing import Keccak256, List, Locksroot, Optional

LEAVES = 0
MERKLEROOT = -1

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.state import MerkleTreeState


def hash_pair(first: Keccak256, second: Optional[Keccak256]) -> Keccak256:
    """ Computes the keccak hash of the elements ordered topologically.

    Since a merkle proof will not include all the elements, but only the path
    starting from the leaves up to the root, the order of the elements is not
    known by the proof checker. The topological order is used as a
    deterministic way of ordering the elements making sure the smart contract
    verification and the python code are compatible.
    """
    assert first is not None

    if second is None:
        return first

    if first > second:
        return sha3(second + first)

    return sha3(first + second)


def compute_layers(elements: List[Keccak256]) -> List[List[Keccak256]]:
    """ Computes the layers of the merkletree.

    First layer is the list of elements and the last layer is a list with a
    single entry, the merkleroot.
    """

    elements = list(elements)  # consume generators
    assert elements, 'Use make_empty_merkle_tree if there are no elements'

    if not all(isinstance(item, bytes) for item in elements):
        raise ValueError('all elements must be bytes')

    if any(len(item) != 32 for item in elements):
        raise HashLengthNot32()

    if len(elements) != len(set(elements)):
        raise ValueError('Duplicated element')

    leaves = sorted(item for item in elements)
    tree = [leaves]

    layer = leaves
    while len(layer) > 1:
        paired_items = split_in_pairs(layer)
        layer = [hash_pair(a, b) for a, b in paired_items]
        tree.append(layer)

    return tree


def compute_merkleproof_for(merkletree: 'MerkleTreeState', element: Keccak256) -> List[Keccak256]:
    """ Containment proof for element.

    The proof contains only the entries that are sufficient to recompute the
    merkleroot, from the leaf `element` up to `root`.

    Raises:
        IndexError: If the element is not part of the merkletree.
    """
    idx = merkletree.layers[LEAVES].index(element)

    proof = []
    for layer in merkletree.layers:
        if idx % 2:
            pair = idx - 1
        else:
            pair = idx + 1

        # with an odd number of elements the rightmost one does not have a pair.
        if pair < len(layer):
            proof.append(layer[pair])

        # the tree is binary and balanced
        idx = idx // 2

    return proof


def validate_proof(proof: List[Keccak256], root: Keccak256, leaf_element: Keccak256) -> bool:
    """ Checks that `leaf_element` was contained in the tree represented by
    `merkleroot`.
    """

    hash_ = leaf_element
    for pair in proof:
        hash_ = hash_pair(hash_, pair)

    return hash_ == root


def merkleroot(merkletree: 'MerkleTreeState') -> Locksroot:
    """ Return the root element of the merkle tree. """
    assert merkletree.layers, 'the merkle tree layers are empty'
    assert merkletree.layers[MERKLEROOT], 'the root layer is empty'

    return Locksroot(merkletree.layers[MERKLEROOT][0])


def merkle_leaves_from_packed_data(packed_data: bytes) -> List[Keccak256]:
    number_of_bytes = len(packed_data)
    leaves = []
    for i in range(0, number_of_bytes, 96):
        leaves.append(sha3(packed_data[i: i + 96]))
    return leaves
