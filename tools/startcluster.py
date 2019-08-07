#!/usr/bin/env python
import random
import tempfile
from signal import SIGINT, SIGTERM, Signals, signal
from types import FrameType
from typing import ContextManager

from eth_utils import keccak, remove_0x_prefix
from web3 import HTTPProvider, Web3

from raiden.tests.fixtures.constants import DEFAULT_BALANCE
from raiden.tests.utils.eth_node import (
    AccountDescription,
    EthNodeDescription,
    GenesisDescription,
    run_private_blockchain,
)
from raiden.utils import privatekey_to_address, sha3
from raiden.utils.http import JSONRPCExecutor
from raiden.utils.typing import ChainID, List, Port, PrivateKey, TokenAmount
from raiden_contracts.constants import NETWORKNAME_TO_ID

NUM_GETH_NODES = 3
NUM_RAIDEN_ACCOUNTS = 10
START_PORT = 30301
START_RPCPORT = 8101


DEFAULT_ACCOUNTS_SEEDS = [
    "127.0.0.1:{}".format(START_PORT + i).encode() for i in range(NUM_RAIDEN_ACCOUNTS)
]
DEFAULT_ACCOUNTS_KEYS: List[PrivateKey] = [
    PrivateKey(keccak(seed)) for seed in DEFAULT_ACCOUNTS_SEEDS
]
DEFAULT_ACCOUNTS = [
    AccountDescription(privatekey_to_address(key), TokenAmount(DEFAULT_BALANCE))
    for key in DEFAULT_ACCOUNTS_KEYS
]


def main() -> None:
    tmpdir = tempfile.mkdtemp()

    geth_nodes = []
    for i in range(NUM_GETH_NODES):
        is_miner = i == 0
        node_key = PrivateKey(sha3(f"node:{i}".encode()))
        p2p_port = Port(START_PORT + i)
        rpc_port = Port(START_RPCPORT + i)

        description = EthNodeDescription(
            private_key=node_key,
            rpc_port=rpc_port,
            p2p_port=p2p_port,
            miner=is_miner,
            extra_config={},
        )

        geth_nodes.append(description)

    rpc_endpoint = f"http://127.0.0.1:{START_RPCPORT}"
    web3 = Web3(HTTPProvider(rpc_endpoint))

    random_marker = remove_0x_prefix(hex(random.getrandbits(100)))
    genesis_description = GenesisDescription(
        prefunded_accounts=DEFAULT_ACCOUNTS,
        random_marker=random_marker,
        chain_id=ChainID(NETWORKNAME_TO_ID["smoketest"]),
    )
    private_chain: ContextManager[List[JSONRPCExecutor]] = run_private_blockchain(
        web3=web3,
        eth_nodes=geth_nodes,
        base_datadir=tmpdir,
        log_dir=tmpdir,
        verbosity="info",
        genesis_description=genesis_description,
    )

    with private_chain:
        from IPython import embed

        embed()


def shutdown_handler(_signo: Signals, _stackframe: FrameType) -> None:
    raise SystemExit


if __name__ == "__main__":
    signal(SIGTERM, shutdown_handler)
    signal(SIGINT, shutdown_handler)

    main()
