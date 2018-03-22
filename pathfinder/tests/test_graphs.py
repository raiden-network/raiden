import random
from typing import List
import time
import numpy as np
from pathfinder.token_network import TokenNetwork


def test_routing_benchmark(token_networks: List[TokenNetwork], populate_token_networks: None):
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
