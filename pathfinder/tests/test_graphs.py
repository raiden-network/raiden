import random
from typing import List
import time
import numpy as np
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
        paths = token_network.get_paths(source, target, value, 5, bias=0.0)
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
    paths = token_network.get_paths(addresses[0], addresses[3], 10, 1)
    assert len(paths) == 1
    assert paths[0] == [addresses[0], addresses[1], addresses[2], addresses[3]]
