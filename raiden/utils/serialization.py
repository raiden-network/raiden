import json
from collections import defaultdict

import networkx
from eth_utils import (
    to_checksum_address,
    to_canonical_address,
    to_bytes,
    to_hex,
)

from raiden.utils import typing
from raiden.transfer.merkle_tree import (
    LEAVES,
    compute_layers,
)


class ReferenceCache:
    def __init__(self):
        self._cache = defaultdict(list)

    def add(self, import_path, obj):
        """ Register an instance of a certain class
        into the cache.
        """
        if obj not in self._cache[import_path]:
            self._cache[import_path].append(obj)

    def get(self, import_path, obj):
        """ Check if a certain obj exists for reuse.
        """
        for candidate in self._cache[import_path]:
            if obj == candidate:
                return candidate
        return None


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
    data = [
        (to_canonical_address(edge[0]), to_canonical_address(edge[1]))
        for edge in raw_data
    ]
    return networkx.Graph(data)


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
    return compute_layers(elements)
