#!/usr/bin/python
from gevent import monkey  # isort:skip # noqa

monkey.patch_all()  # isort:skip # noqa

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from http import HTTPStatus
from typing import Dict, List, NewType, Optional, Tuple
from urllib.parse import urlsplit

import gevent
import requests
import structlog
from gevent.queue import JoinableQueue

NODE_SECTION_RE = re.compile("^node[0-9]+")
API_VERSION = "v1"
Address = NewType("Address", str)

log = structlog.get_logger(__name__)


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
    minimum_capacity1: int
    minimum_capacity2: int


@dataclass
class ChannelDeposit:
    """Description of a deposit to a channel."""

    token_address: str
    partner: Address
    endpoint: str
    minimum_capacity: int


def is_successful_reponse(response: requests.Response) -> bool:
    return (
        response is not None
        and response.headers["Content-Type"] == "application/json"
        and response.status_code == HTTPStatus.OK
    )


def is_json_reponse(response: requests.Response) -> bool:
    return response is not None and response.headers["Content-Type"] == "application/json"


def channel_details(endpoint: str, token_address: str, partner: str) -> Optional[Dict]:
    url_channel = f"{endpoint}/api/{API_VERSION}/channels/{token_address}/{partner}"
    channel_response = requests.get(url_channel)

    if not is_json_reponse(channel_response):
        raise RuntimeError("Unexpected response from server, {channel_response}")

    if channel_response.status_code == HTTPStatus.OK:
        return channel_response.json()

    return None


def channel_deposit_if_necessary(channel_details: Dict, deposit: ChannelDeposit) -> None:
    url_channel = (
        f"{deposit.endpoint}/api/{API_VERSION}/"
        f"channels/{deposit.token_address}/{deposit.partner}"
    )

    balance_current = int(channel_details["balance"])
    balance_difference = deposit.minimum_capacity - balance_current
    is_deposit_necessary = balance_difference > 0

    if is_deposit_necessary:
        deposit_current = int(channel_details["total_deposit"])
        deposit_new = deposit_current + balance_difference
        new_total_deposit = {"total_deposit": deposit_new}

        log.info(f"Depositing to channel {deposit}")
        response = requests.patch(url_channel, json=new_total_deposit)
        if not is_successful_reponse(response):
            raise RuntimeError(f"An error ocurrent while depositing to channel {deposit}")
    else:
        log.info(f"Channel exists and has enough capacity {deposit}")


def channel_open_with_the_same_node(
    channels_to_open: List[ChannelNew],
    target_to_depositqueue: Dict[Tuple[str, str], JoinableQueue],
) -> None:
    """As of 0.100.5 channels cannot be open in parallel, starting multiple
    opens at the same time can lead to the HTTP request timing out.  Therefore
    here channels are open one after the other. (Issue #5446).
    """
    for channel_open in channels_to_open:
        channel = channel_details(
            channel_open.endpoint1, channel_open.token_address, channel_open.participant2
        )

        if channel is None:
            channel_open_request = {
                "token_address": channel_open.token_address,
                "partner_address": channel_open.participant2,
                "total_deposit": channel_open.minimum_capacity1,
            }

            log.info(f"Opening {channel_open}")
            url_channel_open = f"{channel_open.endpoint1}/api/{API_VERSION}/channels"
            response = requests.put(url_channel_open, json=channel_open_request)

            if not is_successful_reponse(response):
                raise RuntimeError(f"An error ocurrent while opening channel {channel_open}")

        else:
            deposit = ChannelDeposit(
                channel_open.token_address,
                channel_open.participant2,
                channel_open.endpoint1,
                channel_open.minimum_capacity1,
            )
            channel_deposit_if_necessary(channel, deposit)

        # A deposit only makes sense after the channel is opened.
        deposit = ChannelDeposit(
            channel_open.token_address,
            channel_open.participant1,
            channel_open.endpoint2,
            channel_open.minimum_capacity2,
        )

        log.info(f"Queueing {deposit}")
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

        channel = channel_details(deposit.endpoint, deposit.token_address, deposit.partner)
        if channel is None:
            raise RuntimeError(f"Channel does not exist! {deposit}")
        channel_deposit_if_necessary(channel, deposit)


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

    queue_per_node: Dict[str, List[ChannelNew]] = defaultdict(list)
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

            is_node1_with_less_work = len(queue_per_node[participant1]) < len(
                queue_per_node[participant2]
            )

            if is_node1_with_less_work:
                channel_new = ChannelNew(
                    token_address=token_address,
                    participant1=participant1,
                    participant2=participant2,
                    endpoint1=node_to_endpoint[node1],
                    endpoint2=node_to_endpoint[node2],
                    minimum_capacity1=channel["minimum_capacity1"],
                    minimum_capacity2=channel["minimum_capacity2"],
                )
                queue_per_node[participant1].append(channel_new)
            else:
                channel_new = ChannelNew(
                    token_address=token_address,
                    participant1=participant2,
                    participant2=participant1,
                    endpoint1=node_to_endpoint[node2],
                    endpoint2=node_to_endpoint[node1],
                    minimum_capacity1=channel["minimum_capacity2"],
                    minimum_capacity2=channel["minimum_capacity1"],
                )
                queue_per_node[participant2].append(channel_new)

            # queue used to order deposits
            target = (token_address, channel_new.participant2)
            if target not in target_to_depositqueue:
                target_to_depositqueue[target] = JoinableQueue()

    open_greenlets = set(
        gevent.spawn(channel_open_with_the_same_node, channels_to_open, target_to_depositqueue)
        for channels_to_open in queue_per_node.values()
    )
    deposit_greenlets = [
        gevent.spawn(channel_deposit_with_the_same_node_and_token_network, deposit_queue)
        for deposit_queue in target_to_depositqueue.values()
    ]

    gevent.joinall(open_greenlets, raise_error=True)
    log.info("Opening the channels finished")

    # Because all channels have been opened, there is no more deposits to do,
    # so now one just has to wait for the queues to get empty.
    for queue in target_to_depositqueue.values():
        # Queue` and `JoinableQueue` don't have the method `rawlink`, so
        # `joinall` cannot be used. At the same time calling `join` in the
        # `JoinableQueue` was raising an exception `This operation would block
        # forever` which seems to be a false positive. Using `empty` to
        # circumvent it.
        while not queue.empty():
            gevent.sleep(1)

    log.info("Depositing to the channels finished")
    # The deposit greenlets are infinite loops.
    gevent.killall(deposit_greenlets)


if __name__ == "__main__":
    main()
