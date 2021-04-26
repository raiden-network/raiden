import json
from itertools import count
from json import JSONDecodeError
from typing import Mapping

import gevent
import pkg_resources
import requests
from requests.exceptions import RequestException

import raiden
from raiden.network.rpc.client import JSONRPCClient
from raiden.utils.typing import MYPY_ANNOTATION, BlockNumber, BlockTimeout, Optional
from raiden_contracts.utils.type_aliases import ChainID


def blockcypher_query_with_retries(sleep: float, retries: int = 3) -> Optional[BlockNumber]:
    """Queries blockcypher for latest mainnet block number"""

    def make_request() -> BlockNumber:
        response = requests.get(
            "https://api.blockcypher.com/v1/eth/main",
            headers={
                "ACCEPT": "application/json",
                "USER-AGENT": f"raiden-{pkg_resources.require(raiden.__name__)[0].version}",
            },
        )
        return BlockNumber(json.loads(response.content)["height"])

    for _ in range(retries):
        try:
            return make_request()
        except (RequestException, JSONDecodeError, ValueError, KeyError):
            gevent.sleep(sleep)

    return None


def wait_for_sync_blockcypher(
    rpc_client: JSONRPCClient, tolerance: BlockTimeout, sleep: float
) -> None:
    syncing_str = "\rSyncing ... Current: {} / Target: ~{}"
    error_str = "Could not get blockchain information from blockcypher. Ignoring."

    local_block = rpc_client.block_number()
    blockcypher_block = blockcypher_query_with_retries(sleep)

    if blockcypher_block is None:
        print(error_str)
        return

    if local_block >= blockcypher_block - tolerance:
        return

    print("Waiting for the ethereum node to synchronize. [Use ^C to exit]")
    print(syncing_str.format(local_block, blockcypher_block), end="")

    for i in count():
        gevent.sleep(sleep)
        local_block = rpc_client.block_number()

        # update the oracle block number sparsely to not spam the server
        if local_block >= blockcypher_block or i % 50 == 0:
            blockcypher_block = blockcypher_query_with_retries(sleep)

            if blockcypher_block is None:
                print(error_str, flush=True)
                return

            if local_block >= blockcypher_block - tolerance:
                return

        print(syncing_str.format(local_block, blockcypher_block), end="", flush=True)

    # add a newline so that the next print will start have it's own line
    print("")


def wait_for_sync_rpc_api(
    rpc_client: JSONRPCClient, tolerance: BlockTimeout, sleep: float
) -> None:
    def is_synced(rpc_client: JSONRPCClient) -> bool:
        sync_status = rpc_client.web3.eth.syncing

        # the node is synchronized
        if sync_status is False:
            return True

        assert isinstance(sync_status, Mapping), MYPY_ANNOTATION
        highest_block = sync_status["highestBlock"]

        current_block = rpc_client.block_number()
        if highest_block - current_block > tolerance:
            return False

        return True

    if is_synced(rpc_client):
        return

    print("Waiting for the ethereum node to synchronize [Use ^C to exit].")

    for i in count():
        if i % 3 == 0:
            print("\r", end="")

        print(".", end="", flush=True)

        gevent.sleep(sleep)

        if is_synced(rpc_client):
            return

    # add a newline so that the next print will start have it's own line
    print("")


def wait_for_sync(rpc_client: JSONRPCClient, tolerance: BlockTimeout, sleep: float) -> None:
    # print something since the actual test may take a few moments for the first
    # iteration
    print("Checking if the ethereum node is synchronized")

    # Only use blockcypher on mainnet
    if rpc_client.chain_id == ChainID(1):
        wait_for_sync_blockcypher(rpc_client, tolerance, sleep)

    wait_for_sync_rpc_api(rpc_client, tolerance, sleep)


def blocks_to_sync(rpc_client: JSONRPCClient) -> BlockTimeout:
    sync_status = rpc_client.web3.eth.syncing

    if sync_status is False:
        return BlockTimeout(0)

    assert isinstance(sync_status, Mapping), MYPY_ANNOTATION
    highest_block = sync_status["highestBlock"]

    current_block = rpc_client.block_number()
    return BlockTimeout(highest_block - current_block)
