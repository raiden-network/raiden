# the layers grow from the leaves to the root
from raiden.exceptions import HashLengthNot32
from raiden.utils import sha3, split_in_pairs
from raiden.utils.typing import Keccak256, List, Optional

LEAVES = 0
MERKLEROOT = -1


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
    assert elements, "Use make_empty_merkle_tree if there are no elements"

    if not all(isinstance(item, bytes) for item in elements):
        raise ValueError("all elements must be bytes")

    if any(len(item) != 32 for item in elements):
        raise HashLengthNot32()

    if len(elements) != len(set(elements)):
        raise ValueError("Duplicated element")

    leaves = sorted(item for item in elements)
    tree = [leaves]

    layer = leaves
    while len(layer) > 1:
        paired_items = split_in_pairs(layer)
        layer = [hash_pair(a, b) for a, b in paired_items]
        tree.append(layer)

    return tree


def merkle_leaves_from_packed_data(packed_data: bytes) -> List[Keccak256]:
    number_of_bytes = len(packed_data)
    leaves = []
    for i in range(0, number_of_bytes, 96):
        leaves.append(sha3(packed_data[i : i + 96]))
    return leaves
