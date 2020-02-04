import json
import sys
from itertools import count
from json import JSONDecodeError

import gevent
import pkg_resources
import requests
from requests.exceptions import RequestException

import raiden
from raiden.network.rpc.client import JSONRPCClient
from raiden.utils.typing import BlockNumber, BlockTimeout, Optional
from raiden_contracts.utils.type_aliases import ChainID


def blockcypher_query_with_retries(sleep: float, retries: int = 3) -> Optional[BlockNumber]:
    """ Queries blockcypher for latest mainnet block number """

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
    syncing_str = "\nSyncing ... Current: {} / Target: ~{}"
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
        sys.stdout.flush()
        gevent.sleep(sleep)
        local_block = rpc_client.block_number()

        # update the oracle block number sparsely to not spam the server
        if local_block >= blockcypher_block or i % 50 == 0:
            blockcypher_block = blockcypher_query_with_retries(sleep)

            if blockcypher_block is None:
                print(error_str)
                return

            if local_block >= blockcypher_block - tolerance:
                return

        print(syncing_str.format(local_block, blockcypher_block), end="")

    # add a newline so that the next print will start have it's own line
    print("")


def wait_for_sync_rpc_api(rpc_client: JSONRPCClient, sleep: float) -> None:
    if rpc_client.is_synced():
        return

    print("Waiting for the ethereum node to synchronize [Use ^C to exit].")

    for i in count():
        if i % 3 == 0:
            print("\r", end="")

        print(".", end="")
        sys.stdout.flush()

        gevent.sleep(sleep)

        if rpc_client.is_synced():
            return

    # add a newline so that the next print will start have it's own line
    print("")


def wait_for_sync(rpc_client: JSONRPCClient, tolerance: BlockTimeout, sleep: float) -> None:
    # print something since the actual test may take a few moments for the first
    # iteration
    print("Checking if the ethereum node is synchronized")

    # Only use blockcypher on mainnet
    if rpc_client.chain_id == ChainID(2345):
        wait_for_sync_blockcypher(rpc_client, tolerance, sleep)
    else:
        wait_for_sync_rpc_api(rpc_client, sleep)
