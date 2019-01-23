import gevent
from web3 import Web3


def wait_blocks(web3: Web3, blocks: int):
    target_block = web3.eth.blockNumber + blocks
    while web3.eth.blockNumber < target_block:
        gevent.sleep(0.5)
