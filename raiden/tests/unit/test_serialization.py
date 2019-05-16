import random
from dataclasses import dataclass

import pytest
from eth_utils import to_canonical_address
from networkx import Graph

from raiden.storage.serialization import JSONSerializer
from raiden.tests.utils import factories
from raiden.transfer import state, state_change


@dataclass
class ClassWithGraphObject:
    graph: Graph


def test_decode_with_unknown_type():
    test_str = """
{
    "_type": "some.non.existent.package",
    "attr1": "test"
}
"""
    with pytest.raises(TypeError) as m:
        JSONSerializer.deserialize(test_str)
        assert str(m) == "Module some.non.existent.package does not exist"

    test_str = """
{
    "_type": "raiden.tests.unit.test_serialization.NonExistentClass",
    "attr1": "test"
}
"""
    with pytest.raises(TypeError) as m:
        JSONSerializer.deserialize(test_str)
        assert str(m) == "raiden.tests.unit.test_serialization.NonExistentClass"


def test_serialization_networkx_graph():
    p1 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4C")
    p2 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4D")
    p3 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4E")
    p4 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4F")

    e = [(p1, p2), (p2, p3), (p3, p4)]
    graph = Graph(e)
    instance = ClassWithGraphObject(graph)

    data = JSONSerializer.serialize(instance)
    restored_instance = JSONSerializer.deserialize(data)

    assert instance.graph.edges == restored_instance.graph.edges


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
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
        our_address=our_address,
        chain_id=chain_id,
    )

    decoded_obj = JSONSerializer.deserialize(JSONSerializer.serialize(original_obj))

    assert original_obj == decoded_obj


def test_chainstate_restore():
    pseudo_random_generator = random.Random()
    block_number = 577
    our_address = factories.make_address()
    chain_id = 777

    original_obj = state.ChainState(
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
        our_address=our_address,
        chain_id=chain_id,
    )

    decoded_obj = JSONSerializer.deserialize(JSONSerializer.serialize(original_obj))

    assert original_obj == decoded_obj
