# -*- coding: utf-8 -*-
import pytest

from raiden.api.python import RaidenAPI2
from raiden.tests.utils.transfer import get_channelstate
from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer import channel
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
)
from raiden.utils import address_encoder


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [2])
def test_token_addresses(raiden_network, token_addresses):
    app = raiden_network[0]
    api = RaidenAPI2(app.raiden)
    assert set(api.get_tokens_list()) == set(token_addresses)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_lifecycle(raiden_network, token_addresses, deposit):
    node1, node2 = raiden_network
    token_address = token_addresses[0]

    api1 = RaidenAPI2(node1.raiden)
    api2 = RaidenAPI2(node2.raiden)

    # nodes don't have a channel, so they are not healthchecking
    assert api1.get_node_network_state(api2.address) == NODE_NETWORK_UNKNOWN
    assert api2.get_node_network_state(api1.address) == NODE_NETWORK_UNKNOWN
    assert not api1.get_channel_list(token_address, api2.address)

    # open is a synchronous api
    api1.channel_open(token_address, api2.address)
    channels = api1.get_channel_list(token_address, api2.address)
    assert len(channels) == 1

    channel12 = get_channelstate(node1, node2, token_address)
    assert channel.get_status(channel12) == CHANNEL_STATE_OPENED

    event_list1 = api1.get_channel_events(
        channel12.identifier,
        channel12.open_transaction.finished_block_number,
    )
    assert event_list1 == []

    # Load the new state with the deposit
    api1.channel_deposit(token_address, api2.address, deposit)
    channel12 = get_channelstate(node1, node2, token_address)

    assert channel.get_status(channel12) == CHANNEL_STATE_OPENED
    assert channel.get_balance(channel12.our_state, channel12.partner_state) == deposit
    assert channel12.our_state.contract_balance == deposit
    assert api1.get_channel_list(token_address, api2.address) == [channel12]

    # there is a channel open, they must be healthchecking each other
    assert api1.get_node_network_state(api2.address) == NODE_NETWORK_REACHABLE
    assert api2.get_node_network_state(api1.address) == NODE_NETWORK_REACHABLE

    event_list2 = api1.get_channel_events(
        channel12.identifier,
        channel12.open_transaction.finished_block_number,
    )
    assert any(
        (
            event['_event_type'] == b'ChannelNewBalance' and
            event['participant'] == address_encoder(api1.address)
        )
        for event in event_list2
    )

    api1.channel_close(token_address, api2.address)
    node1.raiden.poll_blockchain_events()

    # Load the new state with the channel closed
    channel12 = get_channelstate(node1, node2, token_address)

    event_list3 = api1.get_channel_events(
        channel12.identifier,
        channel12.open_transaction.finished_block_number,
    )
    assert len(event_list3) > len(event_list2)
    assert any(
        (
            event['_event_type'] == b'ChannelClosed' and
            event['closing_address'] == address_encoder(api1.address)
        )
        for event in event_list3
    )
    assert channel.get_status(channel12) == CHANNEL_STATE_CLOSED

    settlement_block = (
        channel12.close_transaction.finished_block_number +
        channel12.settle_timeout +
        10  # arbitrary number of additional blocks, used to wait for the settle() call
    )
    wait_until_block(node1.raiden.chain, settlement_block)

    # Load the new state with the channel settled
    channel12 = get_channelstate(node1, node2, token_address)

    node1.raiden.poll_blockchain_events()
    assert channel.get_status(channel12) == CHANNEL_STATE_SETTLED
