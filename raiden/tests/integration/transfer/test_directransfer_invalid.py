import random

import pytest

from raiden.api.python import RaidenAPI
from raiden.constants import UINT64_MAX
from raiden.messages import DirectTransfer
from raiden.tests.utils.factories import (
    UNIT_CHAIN_ID,
    UNIT_SECRETHASH,
    make_address,
    make_privkey_address,
)
from raiden.tests.utils.geth import wait_until_block
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    get_channelstate,
    sign_and_inject,
)
from raiden.transfer import channel, views
from raiden.transfer.state import EMPTY_MERKLE_ROOT


@pytest.mark.skip(reason='direct_transfer_async doesnt return AsyncResult anymore')
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_failsfast_directtransfer_exceeding_distributable(
        raiden_network,
        token_addresses,
        deposit,
):

    alice_app, bob_app = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(alice_app)
    payment_network_id = alice_app.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    async_result = alice_app.raiden.direct_transfer_async(
        token_network_identifier,
        deposit * 2,
        bob_app.raiden.address,
        identifier=1,
    )
    assert not async_result.get_nowait()


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidtoken(raiden_network, deposit, token_addresses):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    channel0 = get_channelstate(app0, app1, token_network_identifier)
    message_identifier = random.randint(0, UINT64_MAX)

    payment_identifier = 1
    invalid_token_address = make_address()
    channel_identifier = channel0.identifier
    direct_transfer_message = DirectTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=1,
        token_network_address=token_network_identifier,
        token=invalid_token_address,
        channel_identifier=channel_identifier,
        transferred_amount=0,
        locked_amount=0,
        recipient=app1.raiden.address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    sign_and_inject(
        direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synced_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidlocksroot(raiden_network, token_addresses):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    channel0 = get_channelstate(app0, app1, token_network_identifier)
    balance0 = channel.get_balance(channel0.our_state, channel0.partner_state)
    balance1 = channel.get_balance(channel0.partner_state, channel0.our_state)

    payment_identifier = 1
    invalid_locksroot = UNIT_SECRETHASH
    channel_identifier = channel0.identifier
    message_identifier = random.randint(0, UINT64_MAX)

    direct_transfer_message = DirectTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=1,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel_identifier,
        transferred_amount=0,
        locked_amount=0,
        recipient=app1.raiden.address,
        locksroot=invalid_locksroot,
    )

    sign_and_inject(
        direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synced_channel_state(
        token_network_identifier,
        app0, balance0, [],
        app1, balance1, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidsender(raiden_network, deposit, token_addresses):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    other_key, other_address = make_privkey_address()
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    channel0 = get_channelstate(app0, app1, token_network_identifier)
    channel_identifier = channel0.identifier
    message_identifier = random.randint(0, UINT64_MAX)

    direct_transfer_message = DirectTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=1,
        nonce=1,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel_identifier,
        transferred_amount=10,
        locked_amount=0,
        recipient=app0.raiden.address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    sign_and_inject(
        direct_transfer_message,
        other_key,
        other_address,
        app0,
    )

    assert_synced_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidnonce(raiden_network, deposit, token_addresses):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )
    channel0 = get_channelstate(app0, app1, token_network_identifier)

    transferred_amount = 10
    same_payment_identifier = 1
    message_identifier = random.randint(0, UINT64_MAX)

    event = channel.send_directtransfer(
        channel0,
        transferred_amount,
        message_identifier,
        same_payment_identifier,
    )

    direct_transfer_message = DirectTransfer.from_event(event)
    sign_and_inject(
        direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    # Send a *different* direct transfer with the *same nonce*
    invalid_transferred_amount = transferred_amount // 2
    message_identifier = random.randint(0, UINT64_MAX)

    invalid_direct_transfer_message = DirectTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=same_payment_identifier,
        nonce=1,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=invalid_transferred_amount,
        locked_amount=0,
        recipient=app1.raiden.address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    sign_and_inject(
        invalid_direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synced_channel_state(
        token_network_identifier,
        app0, deposit - transferred_amount, [],
        app1, deposit + transferred_amount, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [30])
def test_received_directtransfer_closedchannel(raiden_network, token_addresses, deposit):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    registry_address = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )
    channel0 = get_channelstate(app0, app1, token_network_identifier)

    RaidenAPI(app1.raiden).channel_close(
        registry_address,
        token_address,
        app0.raiden.address,
    )

    wait_until_block(
        app0.raiden.chain,
        app0.raiden.chain.block_number() + 1,
    )

    # Now receive one direct transfer for the closed channel
    message_identifier = random.randint(0, UINT64_MAX)
    direct_transfer_message = DirectTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=1,
        nonce=1,
        token_network_address=token_network_identifier,
        token=token_address,
        channel_identifier=channel0.identifier,
        transferred_amount=10,
        locked_amount=0,
        recipient=app0.raiden.address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    sign_and_inject(
        direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    # The local state must not change since the channel is already closed
    assert_synced_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )
