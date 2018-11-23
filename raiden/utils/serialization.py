import json

import networkx
from eth_utils import to_bytes, to_canonical_address, to_checksum_address, to_hex

from raiden.transfer.merkle_tree import LEAVES, compute_layers
from raiden.utils import typing


def identity(val):
    return val


def map_dict(
    key_func: typing.Callable,
    value_func: typing.Callable,
    dict: typing.Dict,
) -> typing.Dict[str, typing.Any]:
    return {
        key_func(k): value_func(v)
        for k, v in dict.items()
    }


def map_list(
    value_func: typing.Callable,
    list: typing.List,
) -> typing.List[typing.Any]:
    return [
        value_func(v)
        for v in list
    ]


def serialize_bytes(data: bytes) -> str:
    return to_hex(data)


def deserialize_bytes(data: str) -> bytes:
    return to_bytes(hexstr=data)


def serialize_networkx_graph(graph: networkx.Graph) -> str:
    return json.dumps([
        (to_checksum_address(edge[0]), to_checksum_address(edge[1]))
        for edge in graph.edges
    ])


def deserialize_networkx_graph(data: str) -> networkx.Graph:
    raw_data = json.loads(data)
    canonical_addresses = [
        (to_canonical_address(edge[0]), to_canonical_address(edge[1]))
        for edge in raw_data
    ]
    return networkx.Graph(canonical_addresses)


def serialize_participants_tuple(
    participants: typing.Tuple[typing.Address, typing.Address],
) -> typing.List[str]:
    return [
        to_checksum_address(participants[0]),
        to_checksum_address(participants[1]),
    ]


def deserialize_participants_tuple(
    data: typing.List[str],
) -> typing.Tuple[typing.Address, typing.Address]:
    assert len(data) == 2
    return (
        to_canonical_address(data[0]),
        to_canonical_address(data[1]),
    )


def serialize_merkletree_layers(data) -> typing.List[str]:
    return map_list(serialize_bytes, data[LEAVES])


def deserialize_merkletree_layers(data: typing.List[str]):
    elements = map_list(deserialize_bytes, data)
    if len(elements) == 0:
        return [
            [],           # the leaves are empty
            [bytes(32)],  # the root is the constant 0
        ]

    return compute_layers(elements)


def serialize_queueid_to_queue(data: typing.Dict):
    # QueueId cannot be the key in a JSON dict, so make it a str
    return {
        str(queue_id): (queue_id, queue)
        for queue_id, queue in data.items()
    }


def deserialize_queueid_to_queue(data: typing.Dict):
    return {
        queue_id: queue
        for queue_id, queue in data.values()
    }
