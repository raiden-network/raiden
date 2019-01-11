import random
import time
from math import isclose
from typing import List

import pytest
from networkx import NetworkXNoPath

from pathfinding_service.config import DEFAULT_PERCENTAGE_FEE
from pathfinding_service.model import ChannelView, TokenNetwork
from raiden_libs.types import Address


# This test is boring right now, but should get more interesting as the routing
# gets more options.
def test_edge_weight(addresses):
    a = addresses[0]
    b = addresses[1]
    view = ChannelView(1, a, b)

    assert TokenNetwork.edge_weight(
        dict(),
        dict(view=view),
    ) == 1


def test_routing_benchmark(
    token_network_model: TokenNetwork,
    populate_token_network_random: None,
):
    value = 100
    G = token_network_model.G
    times = []
    start = time.time()
    for _ in range(100):
        tic = time.time()
        source, target = random.sample(G.nodes, 2)
        paths = token_network_model.get_paths(source, target, value=value, max_paths=5, bias=0.0)
        toc = time.time()
        times.append(toc - tic)
    end = time.time()
    for path_object in paths:
        path = path_object['path']
        fees = path_object['estimated_fee']
        for node1, node2 in zip(path[:-1], path[1:]):
            view: ChannelView = G[node1][node2]['view']
            print('fee = ', view.relative_fee, 'capacity = ', view.capacity)
        print('fee sum = ', fees)
    print('Paths: ', paths)
    print('Mean runtime: ', sum(times) / len(times))
    print('Min runtime: ', min(times))
    print('Max runtime: ', max(times))
    print('Total runtime: ', end - start)


def test_routing_simple(
    token_network_model: TokenNetwork,
    populate_token_network_case_1: None,
    addresses: List[Address],
):
    view01: ChannelView = token_network_model.G[addresses[0]][addresses[1]]['view']
    view10: ChannelView = token_network_model.G[addresses[1]][addresses[0]]['view']

    assert view01.deposit == 100
    assert view01.transferred_amount == 0
    assert view01.locked_amount == 0
    assert isclose(view01.relative_fee, DEFAULT_PERCENTAGE_FEE)
    assert view01.capacity == 100
    assert view10.capacity == 50

    # 0->2->3 is the shortest path
    paths = token_network_model.get_paths(
        addresses[0],
        addresses[3],
        value=10,
        max_paths=1,
        hop_bias=1,
    )
    assert len(paths) == 1
    assert paths[0] == {
        'path': [addresses[0], addresses[2], addresses[3]],
        'estimated_fee': 0,
    }

    # Not connected.
    with pytest.raises(NetworkXNoPath):
        token_network_model.get_paths(addresses[0], addresses[5], value=10, max_paths=1)


def test_routing_result_order(
    token_network_model: TokenNetwork,
    populate_token_network_case_1: None,
    addresses: List[Address],
):
    paths = token_network_model.get_paths(
        addresses[0],
        addresses[2],
        value=10,
        max_paths=5,
        hop_bias=1,
    )
    # 5 paths requested, but only 3 are available
    assert len(paths) == 3
    assert paths[0] == {
        'path': [addresses[0], addresses[2]],
        'estimated_fee': 0,
    }
    assert paths[1] == {
        'path': [addresses[0], addresses[1], addresses[2]],
        'estimated_fee': 0,
    }
    assert paths[2] == {
        'path': [addresses[0], addresses[1], addresses[4], addresses[3], addresses[2]],
        'estimated_fee': 0,
    }


def addresses_to_indexes(path, addresses):
    index_of_address = {a: i for i, a in enumerate(addresses)}
    return [index_of_address[a] for a in path]


def test_diversity_penalty(
    token_network_model: TokenNetwork,
    populate_token_network_case_3: None,
    addresses: List[Address],
):
    """ Check changes in routing when increasing diversity penalty """

    def get_paths(diversity_penalty):
        paths = token_network_model.get_paths(
            addresses[0],
            addresses[8],
            value=10,
            max_paths=5,
            hop_bias=1,
            diversity_penalty=diversity_penalty,
        )
        index_paths = [addresses_to_indexes(p['path'], addresses) for p in paths]
        return index_paths

    assert get_paths(0.1) == [
        [0, 7, 8],
        [0, 7, 6, 8],
        [0, 7, 9, 10, 8],
        [0, 7, 6, 5, 8],
        [0, 1, 2, 3, 4, 8],
    ]

    assert get_paths(1.1) == [
        [0, 7, 8],
        [0, 7, 6, 8],
        [0, 1, 2, 3, 4, 8],
        [0, 7, 9, 10, 8],
        [0, 7, 6, 5, 8],
    ]

    assert get_paths(10) == [
        [0, 7, 8],
        [0, 1, 2, 3, 4, 8],
        [0, 7, 6, 8],
        [0, 7, 9, 10, 8],
        [0, 7, 6, 5, 8],
    ]
