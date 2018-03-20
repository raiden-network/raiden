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
        from_address, to_address = random.sample(range(100), 2)
        source, target = list(G.nodes())[from_address], list(G.nodes())[to_address]
        paths = token_network.get_paths(source, target, value, 5)
        toc = time.time()
        times.append(toc - tic)
    end = time.time()
    for path in paths:
        fees = sum(G[A][B]['view'].fee for A, B in zip(path[:-1], path[1:]))
        for A, B in zip(path[:-1], path[1:]):     # <- inefficient
            print('fee = ', G[A][B]['view'].fee, 'capacity = ', G[A][B]['view'].capacity)
        print('fee sum = ', fees)
    print(paths)
    print(np.mean(np.array(times)), np.min(np.array(times)), np.max(np.array(times)))
    print("total_runtime = {}".format(end-start))
