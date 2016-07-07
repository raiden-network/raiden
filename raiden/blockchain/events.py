# -*- coding: utf8 -*-
from ethereum import slogging
from pyethapp.jsonrpc import address_decoder, data_decoder

from raiden.blockchain.abi import (
    CHANNELNEWBALANCE_EVENTID,
    CHANNELNEW_EVENTID,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def decode_topic(topic):
    return int(topic[2:], 16)


def channelnew_filter(channel_manager_address_bin, node_address_bin, jsonrpc_client):
    """ Create a filter for new channels.

    Args:
        channel_manager_address_bin (bin): The deployed channel manager contract address.
        node_address_bin (bin): The node's address that we are listening for new channels.
        event_id (int): The event id.
        jsonrpc_client (pyethapp.rpc_client.JSONRPCClient): json rpc client.

    Return:
        int: The new filter id.
    """
    # node_address_hex = node_address_bin.encode('hex')
    # topics = [
    #     event_id, [node_address_hex, None], [None, node_address_hex],
    # ]
    topics = [CHANNELNEW_EVENTID]

    filter_id = jsonrpc_client.new_filter(
        address=channel_manager_address_bin,
        topics=topics,
    )
    return filter_id


def channelnewbalance_filter(netting_channel_address_bin, node_address_bin, jsonrpc_client):
    topics = [CHANNELNEWBALANCE_EVENTID]

    filter_id = jsonrpc_client.new_filter(
        address=netting_channel_address_bin,
        topics=topics,
    )
    return filter_id
