# -*- coding: utf-8 -*-
import time

from raiden.mtree import Merkletree
from raiden.utils import keccak


def do_test_speed(rounds=100, num_hashes=1000):
    values = [
        keccak(str(i))
        for i in range(num_hashes)
    ]

    start_time = time.time()
    for __ in range(rounds):
        Merkletree(values).merkleroot

    elapsed = time.time() - start_time

    print '%d additions per second' % (num_hashes * rounds / elapsed)


if __name__ == '__main__':
    do_test_speed()
