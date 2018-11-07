import random

import pytest
from eth_utils import to_canonical_address
from networkx import Graph

from raiden.storage.serialize import JSONSerializer
from raiden.tests.utils import factories
from raiden.transfer import state, state_change
from raiden.transfer.merkle_tree import compute_layers
from raiden.transfer.state import EMPTY_MERKLE_TREE
from raiden.utils import serialization


class MockObject(object):
    """ Used for testing JSON encoding/decoding """

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self):
        return {
            key: value
            for key, value in self.__dict__.items()
        }

    @classmethod
    def from_dict(cls, data):
        obj = cls()
        for key, value in data.items():
            setattr(obj, key, value)
        return obj

    def __eq__(self, other):
        if not isinstance(other, MockObject):
            return False
        for key, value in self.__dict__.items():
            if key not in other.__dict__ or value != other.__dict__[key]:
                return False

        return True


def test_object_custom_serialization():
    # Simple encode/decode
    original_obj = MockObject(attr1="Hello", attr2="World")
    decoded_obj = JSONSerializer.deserialize(
        JSONSerializer.serialize(original_obj),
    )

    assert original_obj == decoded_obj

    # Encode/Decode with embedded objects
    embedded_obj = MockObject(amount=1, identifier='123')
    original_obj = MockObject(embedded=embedded_obj)
    decoded_obj = JSONSerializer.deserialize(
        JSONSerializer.serialize(original_obj),
    )

    assert original_obj == decoded_obj
    assert decoded_obj.embedded.amount == 1
    assert decoded_obj.embedded.identifier == '123'


def test_decode_with_unknown_type():
    test_str = """
{
    "_type": "some.non.existent.package",
    "attr1": "test"
}
"""
    with pytest.raises(TypeError) as m:
        JSONSerializer.deserialize(test_str)
        assert str(m) == 'Module some.non.existent.package does not exist'

    test_str = """
{
    "_type": "raiden.tests.unit.test_serialization.NonExistentClass",
    "attr1": "test"
}
"""
    with pytest.raises(TypeError) as m:
        JSONSerializer.deserialize(test_str)
        assert str(m) == 'raiden.tests.unit.test_serialization.NonExistentClass'


def test_serialization_networkx_graph():
    p1 = to_canonical_address('0x5522070585a1a275631ba69c444ac0451AA9Fe4C')
    p2 = to_canonical_address('0x5522070585a1a275631ba69c444ac0451AA9Fe4D')
    p3 = to_canonical_address('0x5522070585a1a275631ba69c444ac0451AA9Fe4E')
    p4 = to_canonical_address('0x5522070585a1a275631ba69c444ac0451AA9Fe4F')

    e = [(p1, p2), (p2, p3), (p3, p4)]
    graph = Graph(e)

    data = serialization.serialize_networkx_graph(graph)
    restored_graph = serialization.deserialize_networkx_graph(data)

    assert graph.edges == restored_graph.edges


def test_serialization_participants_tuple():
    participants = (
        to_canonical_address('0x5522070585a1a275631ba69c444ac0451AA9Fe4C'),
        to_canonical_address('0xEF4f7c9962d8bAa8E268B72EC6DD4BDf09C84397'),
    )

    data = serialization.serialize_participants_tuple(participants)
    restored = serialization.deserialize_participants_tuple(data)

    assert participants == restored


def test_serialization_merkletree_layers():
    hash_0 = b'a' * 32
    hash_1 = b'b' * 32

    leaves = [hash_0, hash_1]
    layers = compute_layers(leaves)

    data = serialization.serialize_merkletree_layers(layers)
    restored = serialization.deserialize_merkletree_layers(data)

    assert layers == restored


def test_serialization_merkletree_layers_empty():
    tree = EMPTY_MERKLE_TREE

    data = serialization.serialize_merkletree_layers(tree.layers)
    restored = serialization.deserialize_merkletree_layers(data)

    assert tree.layers == restored


def test_actioninitchain_restore():
    """ ActionInitChain *must* restore the previous pseudo random generator
    state.

    Message identifiers are used for confirmation messages, e.g. delivered and
    processed messages, therefore it's important for each message identifier to
    not collide with a previous identifier, for this reason the PRNG is used.

    Additionally, during restarts the state changes are reapplied, and it's
    really important for the re-execution of the state changes to be
    deterministic, otherwise undefined behavior may happen. For this reason the
    state of the PRNG must be restored.

    If the above is not respected, the message ids generated during restart
    will not match the previous IDs and the message queues won't be properly
    cleared up.
    """
    pseudo_random_generator = random.Random()
    block_number = 577
    our_address = factories.make_address()
    chain_id = 777

    original_obj = state_change.ActionInitChain(
        pseudo_random_generator,
        block_number,
        our_address,
        chain_id,
    )

    decoded_obj = JSONSerializer.deserialize(
        JSONSerializer.serialize(original_obj),
    )

    assert original_obj == decoded_obj


def test_chainstate_restore():
    pseudo_random_generator = random.Random()
    block_number = 577
    our_address = factories.make_address()
    chain_id = 777

    original_obj = state.ChainState(
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        our_address=our_address,
        chain_id=chain_id,
    )

    decoded_obj = JSONSerializer.deserialize(
        JSONSerializer.serialize(original_obj),
    )

    assert original_obj == decoded_obj
