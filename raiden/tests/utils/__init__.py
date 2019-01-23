import random

import gevent
from web3 import Web3


def get_random_bytes(count):
    """Get an array filed with random numbers"""
    return bytes(
        [random.randint(0, 0xff) for _ in range(count)],
    )


def wait_blocks(web3: Web3, blocks: int):
    target_block = web3.eth.blockNumber + blocks
    while web3.eth.blockNumber < target_block:
        gevent.sleep(0.5)
