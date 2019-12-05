#!/usr/bin/python
from gevent import monkey  # isort:skip # noqa

monkey.patch_all()  # isort:skip # noqa

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from http import HTTPStatus
from typing import Dict, List, NewType, Tuple
from urllib.parse import urlsplit

import gevent
import requests
from gevent.queue import JoinableQueue

NODE_SECTION_RE = re.compile("^node[0-9]+")
API_VERSION = "v1"
Address = NewType("Address", str)


@dataclass
class ChannelNew:
    """Descriptoin of a new channel.

    participant1 will open the channel, then participant2 will deposit in it.
    """

    token_address: str
    participant1: Address
    participant2: Address
    endpoint1: str
    endpoint2: str
    deposit1: int
    deposit2: int


@dataclass
class ChannelDeposit:
    """Description of a deposit to a channel."""

    token_address: str
    partner: Address
    endpoint: str
    deposit: int


def channel_open_with_the_same_node(
    channels_to_open: List[ChannelNew],
    target_to_depositqueue: Dict[Tuple[str, str], JoinableQueue],
) -> None:
    """As of 0.100.5 channels cannot be open in parallel, starting multiple
    opens at the same time can lead to the HTTP request timing out.  Therefore
    here channels are open one after the other. (Issue #5446).
    """
    for channel_open in channels_to_open:
        url_open = f"{channel_open.endpoint1}/api/{API_VERSION}/channels"
        channel_details = {
            "token_address": channel_open.token_address,
            "partner_address": channel_open.participant2,
            "total_deposit": channel_open.deposit1,
        }

        print(url_open)
        response = requests.put(url_open, json=channel_details)

        assert response is not None
        is_json = response.headers["Content-Type"] == "application/json"
        assert is_json, response.headers["Content-Type"]
        assert response.status_code == HTTPStatus.OK, response.json()

        # A deposit only makes sense after the channel is opened.
        deposit = ChannelDeposit(
            token_address=channel_open.token_address,
            partner=channel_open.participant1,
            endpoint=channel_open.endpoint2,
            deposit=channel_open.deposit2,
        )
        target_to_depositqueue[(channel_open.token_address, channel_open.participant2)].put(
            deposit
        )


def channel_deposit_with_the_same_node_and_token_network(deposit_queue: JoinableQueue) -> None:
    """Because of how the ERC20 standard is defined, two concurrent approve
    calls overwrite each other.

    Additionally, to prevent a node from trying to deposit more tokens than it
    has, and by consequence sending an unnecessary transaction, a lock is used.
    (e.g.: When two transactions that are individually valid, but together use
    more than the account's balance). This has the side effect of forbiding
    concurrent deposits on the same token network. (Issue #5447)
    """
    while True:
        deposit = deposit_queue.get()

        url_deposit = (
            f"{deposit.endpoint}/api/{API_VERSION}/"
            f"channels/{deposit.token_address}/{deposit.partner}"
        )
        channel_deposit = {"total_deposit": deposit.deposit}

        print(url_deposit)
        requests.put(url_deposit, json=channel_deposit)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config")

    args = parser.parse_args()

    with open(args.config, "r") as handler:
        config = json.load(handler)

    # validate the endpoints
    node_to_endpoint = dict()
    node_to_address = dict()
    for node_name, node_info in config["nodes"].items():
        if urlsplit(node_info["endpoint"]).scheme == "":
            raise ValueError("'endpoint' must have the protocol defined")

        url_deposit = f"{node_info['endpoint']}/api/{API_VERSION}/address"
        result = requests.get(url_deposit).json()

        if result["our_address"] != node_info["address"]:
            raise ValueError(
                f"Address mismatch, configuration {node_info['address']}, "
                f"API response {result['our_address']}"
            )

        node_to_endpoint[node_name] = node_info["endpoint"]
        node_to_address[node_name] = node_info["address"]

    channelnew_by_opener: Dict[str, List[ChannelNew]] = defaultdict(list)
    target_to_depositqueue: Dict[Tuple[str, str], JoinableQueue] = dict()

    # Schedule the requests to evenly distribute the load. This is important
    # because as of 0.100.5 channel can not be done concurrently, by dividing
    # the load evenly we make sure the channels are open as fast as possible.
    for token_address, channels_to_open in config["networks"].items():
        for channel in channels_to_open:
            node1 = channel["node1"]
            node2 = channel["node2"]

            participant1 = node_to_address[node1]
            participant2 = node_to_address[node2]

            is_participant1_with_less_work = len(channelnew_by_opener[participant1]) > len(
                channelnew_by_opener[participant2]
            )

            if is_participant1_with_less_work:
                channel_new = ChannelNew(
                    token_address=token_address,
                    participant1=participant1,
                    participant2=participant2,
                    endpoint1=node_to_endpoint[node1],
                    endpoint2=node_to_endpoint[node2],
                    deposit1=channel["deposit1"],
                    deposit2=channel["deposit2"],
                )
                channelnew_by_opener[participant1].append(channel_new)
            else:
                channel_new = ChannelNew(
                    token_address=token_address,
                    participant1=participant2,
                    participant2=participant1,
                    endpoint1=node_to_endpoint[node2],
                    endpoint2=node_to_endpoint[node1],
                    deposit1=channel["deposit2"],
                    deposit2=channel["deposit1"],
                )
                channelnew_by_opener[participant2].append(channel_new)

            # queue used to order deposits
            target = (token_address, channel_new.participant2)
            if target not in target_to_depositqueue:
                target_to_depositqueue[target] = JoinableQueue()

    open_greenlets = set(
        gevent.spawn(channel_open_with_the_same_node, channels_to_open, target_to_depositqueue)
        for channels_to_open in channelnew_by_opener.values()
    )
    deposit_greenlets = [
        gevent.spawn(channel_deposit_with_the_same_node_and_token_network, deposit_queue)
        for deposit_queue in target_to_depositqueue.values()
    ]

    gevent.joinall(open_greenlets, raise_error=True)

    # Because all channels have been opened, there is no more deposits to do,
    # so now one just has to wait for the queues to get empty.
    for queue in target_to_depositqueue.values():
        queue.join()

    # The deposit greenlets are infinite loops.
    gevent.killall(deposit_greenlets)


if __name__ == "__main__":
    main()
