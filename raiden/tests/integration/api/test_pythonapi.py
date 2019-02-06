import pytest
from eth_utils import to_checksum_address

from raiden.api.python import RaidenAPI
from raiden.exceptions import DepositMismatch, UnknownTokenAddress
from raiden.tests.utils.events import must_have_event, wait_for_state_change
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
def test_raidenapi_channel_lifecycle(raiden_network, token_addresses, deposit, retry_timeout):
    """Uses RaidenAPI to go through a complete channel lifecycle."""
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

    # Make sure invalid arguments to get_channel_list are caught
    with pytest.raises(UnknownTokenAddress):
        api1.get_channel_list(
            registry_address=registry_address,
            token_address=None,
            partner_address=api2.address,
        )

    # open is a synchronous api
    api1.channel_open(node1.raiden.default_registry.address, token_address, api2.address)
    channels = api1.get_channel_list(registry_address, token_address, api2.address)
    assert len(channels) == 1

    channel12 = get_channelstate(node1, node2, token_network_identifier)
    assert channel.get_status(channel12) == CHANNEL_STATE_OPENED

    channel_event_list1 = api1.get_blockchain_events_channel(
        token_address,
        channel12.partner_state.address,
    )
    assert must_have_event(
        channel_event_list1,
        {
            'event': ChannelEvent.OPENED,
            'args': {
                'participant1': to_checksum_address(api1.address),
                'participant2': to_checksum_address(api2.address),
            },
        },
    )

    network_event_list1 = api1.get_blockchain_events_token_network(token_address)
    assert must_have_event(
        network_event_list1,
        {'event': ChannelEvent.OPENED},
    )

    registry_address = api1.raiden.default_registry.address
    # Check that giving a 0 total deposit is not accepted
    with pytest.raises(DepositMismatch):
        api1.set_total_channel_deposit(
            registry_address=registry_address,
            token_address=token_address,
            partner_address=api2.address,
            total_deposit=0,
        )
    # Load the new state with the deposit
    api1.set_total_channel_deposit(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=api2.address,
        total_deposit=deposit,
    )

    # let's make sure it's idempotent. Same deposit should raise deposit mismatch limit
    with pytest.raises(DepositMismatch):
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
    assert must_have_event(
        event_list2,
        {
            'event': ChannelEvent.DEPOSIT,
            'args': {
                'participant': to_checksum_address(api1.address),
                'total_deposit': deposit,
            },
        },
    )

    api1.channel_close(registry_address, token_address, api2.address)

    # Load the new state with the channel closed
    channel12 = get_channelstate(node1, node2, token_network_identifier)

    event_list3 = api1.get_blockchain_events_channel(
        token_address,
        channel12.partner_state.address,
    )
    assert len(event_list3) > len(event_list2)
    assert must_have_event(
        event_list3,
        {
            'event': ChannelEvent.CLOSED,
            'args': {
                'closing_participant': to_checksum_address(api1.address),
            },
        },
    )
    assert channel.get_status(channel12) == CHANNEL_STATE_CLOSED

    assert wait_for_state_change(
        node1.raiden,
        ContractReceiveChannelSettled,
        {
            'token_network_identifier': token_network_identifier,
            'channel_identifier': channel12.identifier,
        },
        retry_timeout,
    )
