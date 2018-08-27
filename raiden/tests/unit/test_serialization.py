from networkx import Graph
from eth_utils import to_canonical_address

from raiden.utils import serialization


def test_serialization_networkx_graph():
    e = [(1, 2), (2, 3), (3, 4)]
    graph = Graph(e)

    data = serialization.serialize_networkx_graph(graph)
    restored_graph = serialization.deserialize_networkx_graph(data)

    assert graph.edges == restored_graph.edges


def test_serialization_participants_tuple():
    participants = (
        to_canonical_address('0x5522070585a1a275631ba69c444ac0451AA9Fe4C'),
        to_canonical_address('0xEF4f7c9962d8bAa8E268B72EC6DD4BDf09C84397')
    )

    data = serialization.serialize_participants_tuple(participants)
    restored = serialization.deserialize_participants_tuple(data)

    assert participants == restored