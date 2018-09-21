import pytest
from eth_utils import is_same_address, to_normalized_address

from raiden.api.python import RaidenAPI
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.geth import wait_until_block
from raiden.tests.utils.transfer import get_channelstate
from raiden.transfer import channel, views
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_OPENED,
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
)
from raiden.transfer.state_change import ContractReceiveChannelSettled
from raiden_contracts.constants import ChannelEvent


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_token_addresses(raiden_network, token_addresses):
    app = raiden_network[0]
    api = RaidenAPI(app.raiden)
    registry_address = app.raiden.default_registry.address
    assert set(api.get_tokens_list(registry_address)) == set(token_addresses)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_lifecycle(raiden_network, token_addresses, deposit, transport_config):
    node1, node2 = raiden_network
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(node1),
        node1.raiden.default_registry.address,
        token_address,
    )

    api1 = RaidenAPI(node1.raiden)
    api2 = RaidenAPI(node2.raiden)

    registry_address = node1.raiden.default_registry.address

    # nodes don't have a channel, so they are not healthchecking
    assert api1.get_node_network_state(api2.address) == NODE_NETWORK_UNKNOWN
    assert api2.get_node_network_state(api1.address) == NODE_NETWORK_UNKNOWN
    assert not api1.get_channel_list(registry_address, token_address, api2.address)

    # open is a synchronous api
    api1.channel_open(node1.raiden.default_registry.address, token_address, api2.address)
    channels = api1.get_channel_list(registry_address, token_address, api2.address)
    assert len(channels) == 1

    channel12 = get_channelstate(node1, node2, token_network_identifier)
    assert channel.get_status(channel12) == CHANNEL_STATE_OPENED

    event_list1 = api1.get_blockchain_events_channel(
        token_address,
        channel12.partner_state.address,
    )
    assert any(
        (
            event['event'] == ChannelEvent.OPENED and
            is_same_address(
                event['args']['participant1'],
                to_normalized_address(api1.address),
            ) and
            is_same_address(
                event['args']['participant2'],
                to_normalized_address(api2.address),
            )
        )
        for event in event_list1
    )

    token_events = api1.get_blockchain_events_token_network(
        token_address,
    )
    assert token_events[0]['event'] == ChannelEvent.OPENED

    registry_address = api1.raiden.default_registry.address
    # Load the new state with the deposit
    api1.set_total_channel_deposit(
        registry_address,
        token_address,
        api2.address,
        deposit,
    )

    # let's make sure it's idempotent
    api1.set_total_channel_deposit(
        registry_address,
        token_address,
        api2.address,
        deposit,
    )

    channel12 = get_channelstate(node1, node2, token_network_identifier)

    assert channel.get_status(channel12) == CHANNEL_STATE_OPENED
    assert channel.get_balance(channel12.our_state, channel12.partner_state) == deposit
    assert channel12.our_state.contract_balance == deposit
    assert api1.get_channel_list(registry_address, token_address, api2.address) == [channel12]

    # there is a channel open, they must be healthchecking each other
    assert api1.get_node_network_state(api2.address) == NODE_NETWORK_REACHABLE
    assert api2.get_node_network_state(api1.address) == NODE_NETWORK_REACHABLE

    event_list2 = api1.get_blockchain_events_channel(
        token_address,
        channel12.partner_state.address,
    )
    assert any(
        (
            event['event'] == ChannelEvent.DEPOSIT and
            is_same_address(
                event['args']['participant'],
                to_normalized_address(api1.address),
            ) and
            event['args']['total_deposit'] == deposit
        )
        for event in event_list2
    )

    api1.channel_close(registry_address, token_address, api2.address)

    # Load the new state with the channel closed
    channel12 = get_channelstate(node1, node2, token_network_identifier)

    event_list3 = api1.get_blockchain_events_channel(
        token_address,
        channel12.partner_state.address,
    )
    assert len(event_list3) > len(event_list2)
    assert any(
        (
            event['event'] == ChannelEvent.CLOSED and
            is_same_address(
                event['args']['closing_participant'],
                to_normalized_address(api1.address),
            )
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

    state_changes = node1.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    assert must_contain_entry(state_changes, ContractReceiveChannelSettled, {
        'token_network_identifier': token_network_identifier,
        'channel_identifier': channel12.identifier,
    })
