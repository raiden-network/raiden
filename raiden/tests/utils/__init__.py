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


def assert_dicts_are_equal(a: dict, b: dict) -> bool:
    """Compares dicts, but allows ignoring specific values through the
    assert_dicts_are_equal.IGNORE_VALUE object"""
    assert a.keys() == b.keys(), \
        f'Only in a: {a.keys()-b.keys()!r}, only in b: {b.keys()-a.keys()!r}'
    for k in a.keys():
        va, vb = a[k], b[k]
        if assert_dicts_are_equal.IGNORE_VALUE in (va, vb):
            continue
        elif isinstance(va, dict) and isinstance(vb, dict):
            assert assert_dicts_are_equal(va, vb)
        else:
            assert va == vb, f'{va} != {vb}'
    return True


assert_dicts_are_equal.IGNORE_VALUE = object()
