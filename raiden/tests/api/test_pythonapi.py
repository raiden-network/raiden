# -*- coding: utf-8 -*-
import pytest

from raiden.api.python import RaidenAPI
from raiden.exceptions import InvalidState
from raiden.network.protocol import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
)
from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
)
from raiden.utils import get_contract_path, address_encoder


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [2])
def test_token_addresses(raiden_network, token_addresses):
    node1, node2 = raiden_network
    token_address = token_addresses[0]

    api1 = RaidenAPI(node1.raiden)
    api2 = RaidenAPI(node2.raiden)

    assert api1.address == node1.raiden.address

    assert set(api1.tokens) == set(token_addresses)
    assert set(api1.get_tokens_list()) == set(token_addresses)

    channels = api1.get_channel_list(token_address, api2.address)
    assert api1.get_channel_list(token_address) == channels
    assert len(api1.get_channel_list()) == 2

    assert api1.get_node_network_state(api2.address) == NODE_NETWORK_REACHABLE


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('number_of_tokens', [0])
def test_token_registration(raiden_network, tester_chain):
    node1 = raiden_network[0]
    token_amount = 1000

    token_address = node1.raiden.chain.deploy_contract(
        contract_name='HumanStandardToken',
        contract_path=get_contract_path('HumanStandardToken.sol'),
        constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
    )

    api1 = RaidenAPI(node1.raiden)
    assert not api1.get_tokens_list()

    assert api1.manager_address_if_token_registered(token_address) is None

    node1.raiden.poll_blockchain_events()
    assert not api1.get_tokens_list()

    api1.register_token(token_address)

    assert api1.manager_address_if_token_registered(token_address) is not None
    assert api1.get_tokens_list() == [token_address]


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_lifecycle(raiden_network, token_addresses, deposit):
    node1, node2 = raiden_network
    token_address = token_addresses[0]

    api1 = RaidenAPI(node1.raiden)
    api2 = RaidenAPI(node2.raiden)

    # nodes don't have a channel, so they are not healthchecking
    assert api1.get_node_network_state(api2.address) == NODE_NETWORK_UNKNOWN
    assert api2.get_node_network_state(api1.address) == NODE_NETWORK_UNKNOWN
    assert api1.get_channel_list(token_address, api2.address) == []

    # this is a synchronous api
    api1.open(token_address, api2.address)
    channels = api1.get_channel_list(token_address, api2.address)
    assert len(channels) == 1
    channel12 = channels[0]

    event_list1 = api1.get_channel_events(
        channel12.channel_address,
        channel12.external_state.opened_block,
    )
    assert event_list1 == []

    # the channel has no deposit yet
    assert channel12.state == CHANNEL_STATE_OPENED

    api1.deposit(token_address, api2.address, deposit)

    assert channel12.state == CHANNEL_STATE_OPENED
    assert channel12.balance == deposit
    assert channel12.contract_balance == deposit
    assert api1.get_channel_list(token_address, api2.address) == [channel12]

    # there is a channel open, they must be healthchecking each other
    assert api1.get_node_network_state(api2.address) == NODE_NETWORK_REACHABLE
    assert api2.get_node_network_state(api1.address) == NODE_NETWORK_REACHABLE

    event_list2 = api1.get_channel_events(
        channel12.channel_address,
        channel12.external_state.opened_block,
    )
    assert any(
        (
            event['_event_type'] == b'ChannelNewBalance' and
            event['participant'] == address_encoder(api1.address)
        )
        for event in event_list2
    )

    with pytest.raises(InvalidState):
        api1.settle(token_address, api2.address)

    api1.close(token_address, api2.address)
    node1.raiden.poll_blockchain_events()

    event_list3 = api1.get_channel_events(
        channel12.channel_address,
        channel12.external_state.opened_block,
    )
    assert len(event_list3) > len(event_list2)
    assert any(
        (
            event['_event_type'] == b'ChannelClosed' and
            event['closing_address'] == address_encoder(api1.address)
        )
        for event in event_list3
    )
    assert channel12.state == CHANNEL_STATE_CLOSED

    settlement_block = (
        channel12.external_state.closed_block +
        channel12.settle_timeout +
        5  # arbitrary number of additional blocks, used to wait for the settle() call
    )
    wait_until_block(node1.raiden.chain, settlement_block)

    node1.raiden.poll_blockchain_events()
    assert channel12.state == CHANNEL_STATE_SETTLED
