#!/usr/bin/env python
from gevent import monkey  # isort:skip # noqa

monkey.patch_all()  # isort:skip # noqa

import asyncio  # isort:skip # noqa
from raiden.network.transport.matrix.rtc import aiogevent  # isort:skip # noqa

asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())  # isort:skip # noqa

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

NODE_SECTION_RE = re.compile("^node[0-9]+")
API_VERSION = "v1"
Address = NewType("Address", str)

log = structlog.get_logger(__name__)


@dataclass
class ChannelNew:
    """Description of a new channel.

    participant1 will open the channel, then participant2 will deposit in it.
    """

    token_address: str
    participant: Address
    partner: Address
    endpoint: str
    initial_deposit: int


@dataclass
class ChannelDeposit:
    """Description of a deposit to a channel."""

    token_address: str
    partner: Address
    endpoint: str
    minimum_capacity: int


OpenQueue = Dict[str, List[ChannelNew]]
DepositQueue = Dict[Tuple[str, str], List[ChannelDeposit]]


def http_response_is_okay(response: requests.Response) -> bool:
    return (
        response is not None
        and response.headers["Content-Type"] == "application/json"
        and response.status_code == HTTPStatus.OK
    )


def http_response_is_created(response: requests.Response) -> bool:
    return (
        response is not None
        and response.headers["Content-Type"] == "application/json"
        and response.status_code == HTTPStatus.CREATED
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


def necessary_deposit(channel_details: Dict, minimum_capacity: int) -> int:
    balance_current = int(channel_details["balance"])
    return minimum_capacity - balance_current


def channel_open(open_queue: List[ChannelNew]) -> None:
    """As of 0.100.5 channels cannot be opened in parallel, starting multiple
    opens at the same time can lead to the HTTP request timing out.  Therefore
    here channels are opened one after the other. (Issue #5446).
    """
    for channel_open in open_queue:
        channel = channel_details(
            channel_open.endpoint, channel_open.token_address, channel_open.partner
        )
        assert (
            channel is None
        ), "Channel already exists, the operation should not have been scheduled."

        channel_open_request = {
            "token_address": channel_open.token_address,
            "partner_address": channel_open.partner,
            "total_deposit": channel_open.initial_deposit,
        }

        log.info(f"Opening {channel_open}")
        url_channel_open = f"{channel_open.endpoint}/api/{API_VERSION}/channels"
        response = requests.put(url_channel_open, json=channel_open_request)

        assert http_response_is_created(response), (response, response.text)


def channel_deposit_with_the_same_token_network(deposit_queue: List[ChannelDeposit]) -> None:
    """Because of how the ERC20 standard is defined, two concurrent approve
    calls overwrite each other.

    Additionally, to prevent a node from trying to deposit more tokens than it
    has, and by consequence sending an unnecessary transaction, a lock is used.
    (e.g.: When two transactions that are individually valid, but together use
    more than the account's balance). This has the side effect of forbidding
    concurrent deposits on the same token network. (Issue #5447)
    """
    while deposit_queue:
        to_delete = list()

        for pos, channel_deposit in enumerate(deposit_queue):
            channel = channel_details(
                channel_deposit.endpoint, channel_deposit.token_address, channel_deposit.partner
            )

            # The channel doesn't exist yet, wait for the transaction to be
            # mined and the local view of the channel created.
            if channel is None:
                continue

            deposit = necessary_deposit(channel, channel_deposit.minimum_capacity)
            to_delete.append(pos)

            if deposit:
                current_total_deposit = int(channel["total_deposit"])
                new_total_deposit = current_total_deposit + deposit
                deposit_json = {"total_deposit": new_total_deposit}

                log.info(f"Depositing to channel {channel_deposit}")

                url_channel = (
                    f"{channel_deposit.endpoint}/api/{API_VERSION}/"
                    f"channels/{channel_deposit.token_address}/{channel_deposit.partner}"
                )
                response = requests.patch(url_channel, json=deposit_json)

                assert http_response_is_okay(response), (response, response.text)
            else:
                log.info(f"Channel exists and has enough capacity {channel_deposit}")

        for pos in reversed(to_delete):
            deposit_queue.pop(pos)


def queue_channel_open(
    nodeaddress_to_channelopenqueue: OpenQueue,
    nodeaddress_to_channeldepositqueue: DepositQueue,
    channel: Dict,
    token_address: str,
    node_to_address: Dict,
    node_to_endpoint: Dict,
) -> None:
    node1 = channel["node1"]
    node2 = channel["node2"]

    participant1 = node_to_address[node1]
    participant2 = node_to_address[node2]

    minimum_capacity1 = channel["minimum_capacity1"]
    minimum_capacity2 = channel["minimum_capacity2"]

    is_node1_with_less_work = len(nodeaddress_to_channelopenqueue[participant1]) < len(
        nodeaddress_to_channelopenqueue[participant2]
    )

    if is_node1_with_less_work:
        channelnew_participant = participant1
        channelnew_partner = participant2
        channelnew_endpoint = node_to_endpoint[node1]
        channelnew_minimum_capacity = minimum_capacity1
        channeldeposit_partner = participant1
        channeldeposit_endpoint = node_to_endpoint[node2]
        channeldeposit_minimum_capacity = minimum_capacity2
    else:
        channelnew_participant = participant2
        channelnew_partner = participant1
        channelnew_endpoint = node_to_endpoint[node2]
        channelnew_minimum_capacity = minimum_capacity2
        channeldeposit_participant = participant1
        channeldeposit_partner = participant2
        channeldeposit_endpoint = node_to_endpoint[node1]
        channeldeposit_minimum_capacity = minimum_capacity1

    channel_new = ChannelNew(
        token_address=token_address,
        participant=channelnew_participant,
        partner=channelnew_partner,
        endpoint=channelnew_endpoint,
        initial_deposit=channelnew_minimum_capacity,
    )
    nodeaddress_to_channelopenqueue[channelnew_participant].append(channel_new)

    log.info(f"Queueing {channel_new}")

    channel_deposit = ChannelDeposit(
        token_address=token_address,
        partner=channeldeposit_partner,
        endpoint=channeldeposit_endpoint,
        minimum_capacity=channeldeposit_minimum_capacity,
    )
    nodeaddress_to_channeldepositqueue[(token_address, channeldeposit_participant)].append(
        channel_deposit
    )

    log.info(f"Queueing {channel_deposit}")


def queue_channel_deposit(
    nodeaddress_to_channeldepositqueue: DepositQueue,
    channel: Dict,
    current_channel1: Dict,
    current_channel2: Dict,
    token_address: str,
    node_to_address: Dict,
    node_to_endpoint: Dict,
) -> None:
    node1 = channel["node1"]
    node2 = channel["node2"]

    participant1 = node_to_address[node1]
    participant2 = node_to_address[node2]

    endpoint1 = node_to_endpoint[node1]
    endpoint2 = node_to_endpoint[node2]

    minimum_capacity1 = channel["minimum_capacity1"]
    minimum_capacity2 = channel["minimum_capacity2"]

    deposit1 = necessary_deposit(current_channel1, minimum_capacity1)
    if deposit1 > 0:
        channel_deposit = ChannelDeposit(
            token_address=token_address,
            partner=participant2,
            endpoint=endpoint1,
            minimum_capacity=minimum_capacity2,
        )
        nodeaddress_to_channeldepositqueue[(token_address, participant1)].append(channel_deposit)

        log.info(f"Queueing {channel_deposit}")
    else:
        log.info(f"Channel already with enough capacity {current_channel1}")

    deposit2 = necessary_deposit(current_channel2, minimum_capacity2)
    if deposit2 > 0:
        channel_deposit = ChannelDeposit(
            token_address=token_address,
            partner=participant1,
            endpoint=endpoint2,
            minimum_capacity=minimum_capacity1,
        )
        nodeaddress_to_channeldepositqueue[(token_address, participant2)].append(channel_deposit)

        log.info(f"Queueing {channel_deposit}")
    else:
        log.info(f"Channel already with enough capacity {current_channel2}")


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

    nodeaddress_to_channelopenqueue: OpenQueue = defaultdict(list)
    nodeaddress_to_channeldepositqueue: DepositQueue = defaultdict(list)

    # Schedule the requests to evenly distribute the load. This is important
    # because as of 0.100.5 channel cannot be opened concurrently, by dividing
    # the load evenly we make sure the channels are opened as fast as possible.
    for token_address, channels_to_open in config["networks"].items():
        for channel in channels_to_open:
            node1 = channel["node1"]
            node2 = channel["node2"]

            participant1 = node_to_address[node1]
            participant2 = node_to_address[node2]

            current_channel1 = channel_details(
                node_to_endpoint[node1], token_address, participant2
            )
            current_channel2 = channel_details(
                node_to_endpoint[node2], token_address, participant1
            )

            nodes_are_synchronized = bool(current_channel1) == bool(current_channel2)
            msg = (
                f"The channel must exist in both or neither of the nodes.\n"
                f"{current_channel1}\n"
                f"{current_channel2}"
            )
            assert nodes_are_synchronized, msg

            if current_channel1 is None:
                queue_channel_open(
                    nodeaddress_to_channelopenqueue,
                    nodeaddress_to_channeldepositqueue,
                    channel,
                    token_address,
                    node_to_address,
                    node_to_endpoint,
                )
            else:
                assert current_channel1 and current_channel2

                queue_channel_deposit(
                    nodeaddress_to_channeldepositqueue,
                    channel,
                    current_channel1,
                    current_channel2,
                    token_address,
                    node_to_address,
                    node_to_endpoint,
                )

    open_greenlets = set(
        gevent.spawn(channel_open, open_queue)
        for open_queue in nodeaddress_to_channelopenqueue.values()
    )
    deposit_greenlets = set(
        gevent.spawn(channel_deposit_with_the_same_token_network, deposit_queue)
        for deposit_queue in nodeaddress_to_channeldepositqueue.values()
    )

    all_greenlets = set()
    all_greenlets.update(open_greenlets)
    all_greenlets.update(deposit_greenlets)

    gevent.joinall(all_greenlets, raise_error=True)


if __name__ == "__main__":
    main()
