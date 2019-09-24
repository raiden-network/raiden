import json
import sys
from itertools import count

import gevent
import requests
from eth_utils import to_int
from requests.exceptions import RequestException

from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.rpc.client import JSONRPCClient


def etherscan_query_with_retries(url: str, sleep: float, retries: int = 3) -> int:
    def get_result():
        response = requests.get(url)
        return json.loads(response.content)["result"]

    for _ in range(retries - 1):
        try:
            etherscan_block = to_int(hexstr=get_result())
        except (RequestException, ValueError, KeyError):
            gevent.sleep(sleep)
        else:
            return etherscan_block

    etherscan_block = to_int(hexstr=get_result())
    return etherscan_block


def wait_for_sync_etherscan(
    proxy_manager: ProxyManager, url: str, tolerance: int, sleep: float
) -> None:
    local_block = proxy_manager.client.block_number()
    etherscan_block = etherscan_query_with_retries(url, sleep)
    syncing_str = "\rSyncing ... Current: {} / Target: ~{}"

    if local_block >= etherscan_block - tolerance:
        return

    print("Waiting for the ethereum node to synchronize. [Use ^C to exit]")
    print(syncing_str.format(local_block, etherscan_block), end="")

    for i in count():
        sys.stdout.flush()
        gevent.sleep(sleep)
        local_block = proxy_manager.client.block_number()

        # update the oracle block number sparsely to not spam the server
        if local_block >= etherscan_block or i % 50 == 0:
            etherscan_block = etherscan_query_with_retries(url, sleep)

            if local_block >= etherscan_block - tolerance:
                return

        print(syncing_str.format(local_block, etherscan_block), end="")

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


def wait_for_sync(proxy_manager: ProxyManager, url: str, tolerance: int, sleep: float) -> None:
    # print something since the actual test may take a few moments for the first
    # iteration
    print("Checking if the ethereum node is synchronized")

    try:
        wait_for_sync_etherscan(proxy_manager, url, tolerance, sleep)
    except (RequestException, ValueError, KeyError):
        print(f"Cannot use {url}. Request failed")
        print("Falling back to eth_sync api.")

        wait_for_sync_rpc_api(proxy_manager.client, sleep)
