import random
from math import isclose
from typing import List
import time
import numpy as np
import pytest
from _pytest.monkeypatch import MonkeyPatch
from networkx import NetworkXNoPath

import pathfinder.token_network
from pathfinder.model.channel_view import ChannelView
from pathfinder.token_network import TokenNetwork
from pathfinder.utils.types import Address


def test_routing_benchmark(
    token_networks: List[TokenNetwork],
    populate_token_networks_random: None
):
    value = 100
    G = token_networks[0].G
    token_network = token_networks[0]
    times = []
    start = time.time()
    for i in range(100):
        tic = time.time()
        source, target = random.sample(G.nodes, 2)
        paths = token_network.get_paths(source, target, value=value, k=5, bias=0.0)
        toc = time.time()
        times.append(toc - tic)
    end = time.time()
    for path in paths:
        fees = sum(G[node1][node2]['view'].fee for node1, node2 in zip(path[:-1], path[1:]))
        for node1, node2 in zip(path[:-1], path[1:]):
            view = G[node1][node2]['view']
            print('fee = ', view.fee, 'capacity = ', view.capacity)
        print('fee sum = ', fees)
    print(paths)
    print(np.mean(np.array(times)), np.min(np.array(times)), np.max(np.array(times)))
    print("total_runtime = {}".format(end-start))


def test_routing_simple(
    token_networks: List[TokenNetwork],
    populate_token_networks_simple: None,
    addresses: List[Address]
):
    token_network = token_networks[0]

    view01: ChannelView = token_network.G[addresses[0]][addresses[1]]['view']
    view10: ChannelView = token_network.G[addresses[1]][addresses[0]]['view']

    assert view01.deposit == 100
    assert view01.transferred_amount == 20
    assert view01.locked_amount == 0
    assert isclose(view01.fee, 0.001)
    assert view01.capacity == 90
    assert view10.capacity == 60

    # 0->1->4->3 is as short as 0->1->2->3 but the shortcut 1->4 is a lot more expensive.
    # 0->2->3 would be shorter but 0->2 is degraded.
    paths = token_network.get_paths(addresses[0], addresses[3], value=10, k=1, hop_bias=0)
    assert len(paths) == 1
    assert paths[0] == [addresses[0], addresses[1], addresses[2], addresses[3]]

    # Bottleneck should be 0->1 and 2->3 with a capacity of 90.
    with pytest.raises(NetworkXNoPath):
        token_network.get_paths(addresses[0], addresses[3], value=100, k=1)

    # Not connected.
    with pytest.raises(NetworkXNoPath):
        token_network.get_paths(addresses[0], addresses[5], value=10, k=1)


def test_routing_disjoint(
    token_networks: List[TokenNetwork],
    populate_token_networks_simple: None,
    addresses: List[Address],
    monkeypatch: MonkeyPatch
):
    token_network = token_networks[0]

    # Paths should be "as disjoint as possible". There are only 2 different paths though.
    monkeypatch.setattr(pathfinder.token_network, 'DIVERSITY_PEN_DEFAULT', 1)
    paths = token_network.get_paths(addresses[0], addresses[2], value=10, k=3)
    assert len(paths) == 2
    assert paths[0] == [addresses[0], addresses[1], addresses[2]]
    assert paths[1] == [addresses[0], addresses[1], addresses[4], addresses[3], addresses[2]]


def test_routing_hop_fee_balance(
    token_networks: List[TokenNetwork],
    populate_token_networks_simple: None,
    addresses: List[Address]
):
    token_network = token_networks[0]

    # 1->4 has an extremely high fee, so 1->2->3->4 would be cheaper but slower.
    # Prefer cheap over fast.
    paths = token_network.get_paths(addresses[1], addresses[4], value=10, k=1, hop_bias=0)
    assert paths[0] == [addresses[1], addresses[2], addresses[3], addresses[4]]
    # Prefer fast over cheap.
    paths = token_network.get_paths(addresses[1], addresses[4], value=10, k=1, hop_bias=1)
    assert paths[0] == [addresses[1], addresses[4]]
