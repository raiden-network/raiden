# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    direct_transfer,
)
from raiden.exceptions import (
    NoPathError,
    InsufficientFunds,
)
from raiden.api.python import RaidenAPI

# Use a large enough settle timeout to have valid transfer messages
TEST_TOKEN_SWAP_SETTLE_TIMEOUT = (
    5 +  # reveal timeout
    7 +  # maker expiration
    7    # taker expiration
)


@pytest.mark.parametrize('number_of_nodes', [3])
def test_get_channel_list(raiden_network, token_addresses):
    app0, app1, app2 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = channel(app0, app1, token_addresses[0])
    channel1 = channel(app1, app0, token_addresses[0])
    channel2 = channel(app0, app2, token_addresses[0])

    api0 = RaidenAPI(app0.raiden)
    api1 = RaidenAPI(app1.raiden)
    api2 = RaidenAPI(app2.raiden)

    assert channel0, channel2 in api0.get_channel_list()
    assert channel0 in api0.get_channel_list(partner_address=app1.raiden.address)
    assert channel1 in api1.get_channel_list(token_address=token_addresses[0])
    assert channel1 in api1.get_channel_list(token_addresses[0], app0.raiden.address)
    assert not api1.get_channel_list(partner_address=app2.raiden.address)

    assert not api1.get_channel_list(
        token_address=token_addresses[0],
        partner_address=app2.raiden.address,
    )

    assert not api2.get_channel_list(
        token_address=app2.raiden.address,
    )


@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('register_tokens', [False])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_register_token(raiden_chain, token_addresses):
    app0, _ = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    api0 = RaidenAPI(app0.raiden)
    assert api0.manager_address_if_token_registered(token_addresses[0]) is None

    manager_0token = api0.register_token(token_addresses[0])

    assert manager_0token == api0.manager_address_if_token_registered(token_addresses[0])

    # Exception if we try to reregister
    with pytest.raises(ValueError):
        api0.register_token(token_addresses[0])


@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('register_tokens', [False])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_second_manager_address_if_token_registered(raiden_chain, token_addresses):
    """Test recreating the scenario described on issue:
    https://github.com/raiden-network/raiden/issues/784"""
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    api0 = RaidenAPI(app0.raiden)
    api1 = RaidenAPI(app1.raiden)

    # Recreate the race condition by making sure the non-registering app won't
    # register at all by watching for the TokenAdded blockchain event.
    app1.raiden.alarm.remove_callback(app1.raiden.poll_blockchain_events)

    manager_0token = api0.register_token(token_addresses[0])
    # The second node does not register but just confirms token is registered.
    # This is the behaviour the api call implement in register_token().
    manager_1token = api1.manager_address_if_token_registered(token_addresses[0])

    assert manager_0token == manager_1token

    # Now make sure the token lists are populated for both nodes
    tokens0_list = api0.get_tokens_list()
    tokens1_list = api1.get_tokens_list()
    assert tokens0_list == tokens1_list
    assert len(tokens1_list) == 1
    assert token_addresses[0] == tokens1_list[0]


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_deposit_updates_balance_immediately(raiden_chain, token_addresses):
    """Test that the balance of a channel gets updated by the deposit() call
    immediately and without having to wait for the `ContractReceiveBalance`
    message since the API needs to return the channel with the deposit balance
    updated"""
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    api0 = RaidenAPI(app0.raiden)

    token_address = token_addresses[0]
    channel_0_1 = channel(app0, app1, token_address)
    old_balance = channel_0_1.contract_balance
    returned_channel = api0.deposit(token_address, app1.raiden.address, 10)
    assert returned_channel.contract_balance == old_balance + 10


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_transfer_to_unknownchannel(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    with pytest.raises(NoPathError):
        RaidenAPI(app0.raiden).transfer(
            graph0.token_address,
            10,
            # sending to an unknown/non-existant address
            target=b'\xf0\xef3\x01\xcd\xcfe\x0f4\x9c\xf6d\xa2\x01?X4\x84\xa9\xf1',
            timeout=10
        )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [2])
@pytest.mark.parametrize('settle_timeout', [TEST_TOKEN_SWAP_SETTLE_TIMEOUT])
def test_token_swap(raiden_network, deposit, settle_timeout):
    app0, app1 = raiden_network

    maker_address = app0.raiden.address
    taker_address = app1.raiden.address

    maker_token, taker_token = list(app0.raiden.token_to_channelgraph.keys())[:2]
    maker_amount = 70
    taker_amount = 30

    identifier = 313
    RaidenAPI(app1.raiden).expect_token_swap(
        identifier,
        maker_token,
        maker_amount,
        maker_address,
        taker_token,
        taker_amount,
        taker_address,
    )

    async_result = RaidenAPI(app0.raiden).token_swap_async(
        identifier,
        maker_token,
        maker_amount,
        maker_address,
        taker_token,
        taker_amount,
        taker_address,
    )

    assert async_result.wait()

    # wait for the taker to receive and process the messages
    gevent.sleep(0.5)

    assert_synched_channels(
        channel(app0, app1, maker_token), deposit - maker_amount, [],
        channel(app1, app0, maker_token), deposit + maker_amount, [],
    )

    assert_synched_channels(
        channel(app0, app1, taker_token), deposit + taker_amount, [],
        channel(app1, app0, taker_token), deposit - taker_amount, [],
    )


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_channel_events(raiden_chain):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_address = app0.raiden.default_registry.token_addresses()[0]
    channel_0_1 = channel(app0, app1, token_address)

    amount = 30
    direct_transfer(
        app0,
        app1,
        token_address,
        amount,
        identifier=1,
    )

    results = RaidenAPI(app0.raiden).get_channel_events(channel_0_1.channel_address, 0)
    assert len(results) == 3
    max_block = 0
    for idx, result in enumerate(results):
        if result['block_number'] > max_block:
            max_block = result['block_number']
            assert max_block != 0

        if idx == 2:
            assert result['_event_type'] == b'EventTransferSentSuccess'
            assert result['amount'] == amount
            assert result['target'] == app1.raiden.address
        else:
            assert result['_event_type'] == b'ChannelNewBalance'

    assert max_block != 0

    results = RaidenAPI(app0.raiden).get_channel_events(
        channel_0_1.channel_address, max_block + 1, max_block + 100
    )
    assert not results


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.xfail
def test_insufficient_funds(raiden_network):
    """Test transfer on a channel with insufficient funds. It is expected to
    fail, as at the moment RaidenAPI is mocked and will always succeed."""
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    with pytest.raises(InsufficientFunds):
        RaidenAPI(app0.raiden).transfer(
            graph0.token_address,
            99999999999999999999,
            target=app1.raiden.address,
            timeout=10
        )
