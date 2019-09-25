import pytest
from eth_utils import to_checksum_address

from raiden.api.python import RaidenAPI
from raiden.exceptions import (
    DepositMismatch,
    InvalidSettleTimeout,
    TokenNotRegistered,
    UnexpectedChannelState,
    UnknownTokenAddress,
)
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import must_have_event, wait_for_state_change
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.transfer import get_channelstate
from raiden.transfer import channel, views
from raiden.transfer.state import ChannelState, NetworkState
from raiden.transfer.state_change import ContractReceiveChannelSettled
from raiden_contracts.constants import ChannelEvent


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_token_addresses(raiden_network, token_addresses):
    """
    Test that opening a channel via the API provides the confirmed block and not
    the latest block. The discrepancy there lead to potential timing issues where
    the token network was deployed for the state in the "latest" block but not yet
    in the confirmed state and a BadFunctionCallOutput exception was thrown from web3.

    Regression test for 4470
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    # Find block where the token network was deployed
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    last_number = app0.raiden.rpc_client.block_number()

    for block_number in range(last_number, 0, -1):
        code = app0.raiden.rpc_client.web3.eth.getCode(
            to_checksum_address(token_network_address), block_number
        )
        if code == b"":
            break
    token_network_deploy_block_number = block_number + 1

    api0 = RaidenAPI(app0.raiden)
    # Emulate the confirmed block being a block where TokenNetwork for token_address
    # has not been deployed.
    views.state_from_raiden(app0.raiden).block_hash = app0.raiden.rpc_client.get_block(
        token_network_deploy_block_number - 1
    )["hash"]

    msg = (
        "Opening a channel with a confirmed block where the token network "
        "has not yet been deployed should raise a TokenNotRegistered error"
    )
    with pytest.raises(TokenNotRegistered):
        api0.channel_open(
            registry_address=app0.raiden.default_registry.address,
            token_address=token_address,
            partner_address=app1.raiden.address,
        )

        pytest.fail(msg)


def run_test_token_addresses(raiden_network, token_addresses):
    app = raiden_network[0]
    api = RaidenAPI(app.raiden)
    registry_address = app.raiden.default_registry.address
    assert set(api.get_tokens_list(registry_address)) == set(token_addresses)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_raidenapi_channel_lifecycle(
    raiden_network, token_addresses, deposit, retry_timeout, settle_timeout_max
):
    """Uses RaidenAPI to go through a complete channel lifecycle."""
    node1, node2 = raiden_network
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(node1), node1.raiden.default_registry.address, token_address
    )

    api1 = RaidenAPI(node1.raiden)
    api2 = RaidenAPI(node2.raiden)

    registry_address = node1.raiden.default_registry.address

    # nodes don't have a channel, so they are not healthchecking
    assert api1.get_node_network_state(api2.address) == NetworkState.UNKNOWN
    assert api2.get_node_network_state(api1.address) == NetworkState.UNKNOWN
    assert not api1.get_channel_list(registry_address, token_address, api2.address)

    # Make sure invalid arguments to get_channel_list are caught
    with pytest.raises(UnknownTokenAddress):
        api1.get_channel_list(
            registry_address=registry_address, token_address=None, partner_address=api2.address
        )

    address_for_lowest_settle_timeout = make_address()
    lowest_valid_settle_timeout = node1.raiden.config["reveal_timeout"] * 2

    # Make sure a small settle timeout is not accepted when opening a channel
    with pytest.raises(InvalidSettleTimeout):
        api1.channel_open(
            registry_address=node1.raiden.default_registry.address,
            token_address=token_address,
            partner_address=address_for_lowest_settle_timeout,
            settle_timeout=lowest_valid_settle_timeout - 1,
        )

    # Make sure a the smallest settle timeout is accepted
    api1.channel_open(
        registry_address=node1.raiden.default_registry.address,
        token_address=token_address,
        partner_address=address_for_lowest_settle_timeout,
        settle_timeout=lowest_valid_settle_timeout,
    )

    address_for_highest_settle_timeout = make_address()
    highest_valid_settle_timeout = settle_timeout_max

    # Make sure a large settle timeout is not accepted when opening a channel
    with pytest.raises(InvalidSettleTimeout):
        api1.channel_open(
            registry_address=node1.raiden.default_registry.address,
            token_address=token_address,
            partner_address=address_for_highest_settle_timeout,
            settle_timeout=highest_valid_settle_timeout + 1,
        )

    # Make sure the highest settle timeout is accepted
    api1.channel_open(
        registry_address=node1.raiden.default_registry.address,
        token_address=token_address,
        partner_address=address_for_highest_settle_timeout,
        settle_timeout=highest_valid_settle_timeout,
    )

    # open is a synchronous api
    api1.channel_open(node1.raiden.default_registry.address, token_address, api2.address)
    channels = api1.get_channel_list(registry_address, token_address, api2.address)
    assert len(channels) == 1

    channel12 = get_channelstate(node1, node2, token_network_address)
    assert channel.get_status(channel12) == ChannelState.STATE_OPENED

    channel_event_list1 = api1.get_blockchain_events_channel(
        token_address, channel12.partner_state.address
    )
    assert must_have_event(
        channel_event_list1,
        {
            "event": ChannelEvent.OPENED,
            "args": {
                "participant1": to_checksum_address(api1.address),
                "participant2": to_checksum_address(api2.address),
            },
        },
    )

    network_event_list1 = api1.get_blockchain_events_token_network(token_address)
    assert must_have_event(network_event_list1, {"event": ChannelEvent.OPENED})

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
        api1.set_total_channel_deposit(registry_address, token_address, api2.address, deposit)

    channel12 = get_channelstate(node1, node2, token_network_address)

    assert channel.get_status(channel12) == ChannelState.STATE_OPENED
    assert channel.get_balance(channel12.our_state, channel12.partner_state) == deposit
    assert channel12.our_state.contract_balance == deposit
    assert api1.get_channel_list(registry_address, token_address, api2.address) == [channel12]

    # there is a channel open, they must be healthchecking each other
    assert api1.get_node_network_state(api2.address) == NetworkState.REACHABLE
    assert api2.get_node_network_state(api1.address) == NetworkState.REACHABLE

    event_list2 = api1.get_blockchain_events_channel(
        token_address, channel12.partner_state.address
    )
    assert must_have_event(
        event_list2,
        {
            "event": ChannelEvent.DEPOSIT,
            "args": {"participant": to_checksum_address(api1.address), "total_deposit": deposit},
        },
    )

    api1.channel_close(registry_address, token_address, api2.address)

    # Load the new state with the channel closed
    channel12 = get_channelstate(node1, node2, token_network_address)

    event_list3 = api1.get_blockchain_events_channel(
        token_address, channel12.partner_state.address
    )
    assert len(event_list3) > len(event_list2)
    assert must_have_event(
        event_list3,
        {
            "event": ChannelEvent.CLOSED,
            "args": {"closing_participant": to_checksum_address(api1.address)},
        },
    )
    assert channel.get_status(channel12) == ChannelState.STATE_CLOSED

    with pytest.raises(UnexpectedChannelState):
        api1.set_total_channel_deposit(
            registry_address, token_address, api2.address, deposit + 100
        )

    assert wait_for_state_change(
        node1.raiden,
        ContractReceiveChannelSettled,
        {
            "canonical_identifier": {
                "token_network_address": token_network_address,
                "channel_identifier": channel12.identifier,
            }
        },
        retry_timeout,
    )
