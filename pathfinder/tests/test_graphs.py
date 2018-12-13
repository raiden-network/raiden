import random
import time
from math import isclose
from typing import List

import numpy as np
import pytest
from _pytest.monkeypatch import MonkeyPatch
from networkx import NetworkXNoPath

import pathfinder.model.token_network
from pathfinder.config import DEFAULT_PERCENTAGE_FEE
from pathfinder.model import ChannelView, TokenNetwork
from raiden_libs.types import Address


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
        paths = token_network_model.get_paths(source, target, value=value, k=5, bias=0.0)
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
    print(paths)
    print(np.mean(np.array(times)), np.min(np.array(times)), np.max(np.array(times)))
    print("total_runtime = {}".format(end-start))


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

    # 0->1->4->3 is as short as 0->1->2->3 but the shortcut 1->4 is a lot more expensive.
    # 0->2->3 would be shorter but 0->2 is degraded.
    paths = token_network_model.get_paths(addresses[0], addresses[3], value=10, k=1, hop_bias=1)
    assert len(paths) == 1
    assert paths[0] == {
        'path': [addresses[0], addresses[2], addresses[3]],
        'estimated_fee': 0,
    }

    # Bottleneck should be 0->1 and 2->3 with a capacity of 90.
    with pytest.raises(NetworkXNoPath):
        token_network_model.get_paths(addresses[0], addresses[3], value=100, k=1)

    # Not connected.
    with pytest.raises(NetworkXNoPath):
        token_network_model.get_paths(addresses[0], addresses[5], value=10, k=1)
