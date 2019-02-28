#!/usr/bin/env python
import random
import signal
import tempfile

from eth_utils import remove_0x_prefix
from web3 import HTTPProvider, Web3

from raiden.tests.utils.eth_node import EthNodeDescription, run_private_blockchain
from raiden.utils import privatekey_to_address, sha3
from raiden_contracts.constants import NETWORKNAME_TO_ID

NUM_GETH_NODES = 3
NUM_RAIDEN_ACCOUNTS = 10
START_PORT = 30301
START_RPCPORT = 8101


DEFAULT_ACCOUNTS_SEEDS = [
    '127.0.0.1:{}'.format(START_PORT + i).encode()
    for i in range(NUM_RAIDEN_ACCOUNTS)
]
DEFAULT_ACCOUNTS_KEYS = [
    sha3(seed)
    for seed in DEFAULT_ACCOUNTS_SEEDS
]
DEFAULT_ACCOUNTS = [
    privatekey_to_address(key)
    for key in DEFAULT_ACCOUNTS_KEYS
]


def main():
    tmpdir = tempfile.mkdtemp()

    geth_nodes = []
    for i in range(NUM_GETH_NODES):
        is_miner = i == 0
        node_key = sha3(f'node:{i}'.encode())
        p2p_port = START_PORT + i
        rpc_port = START_RPCPORT + i

        description = EthNodeDescription(
            private_key=node_key,
            rpc_port=rpc_port,
            p2p_port=p2p_port,
            miner=is_miner,
        )

        geth_nodes.append(description)

    rpc_endpoint = f'http://127.0.0.1:{START_RPCPORT}'
    web3 = Web3(HTTPProvider(rpc_endpoint))

    verbosity = 0
    random_marker = remove_0x_prefix(hex(random.getrandbits(100)))
    geth_processes = run_private_blockchain(  # NOQA
        web3=web3,
        accounts_to_fund=DEFAULT_ACCOUNTS,
        eth_nodes=geth_nodes,
        base_datadir=tmpdir,
        log_dir=tmpdir,
        chain_id=NETWORKNAME_TO_ID['smoketest'],
        verbosity=verbosity,
        random_marker=random_marker,
    )

    from IPython import embed
    embed()


def shutdown_handler(_signo, _stackframe):
    raise SystemExit


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    main()
