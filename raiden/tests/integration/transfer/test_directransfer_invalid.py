# -*- coding: utf-8 -*-
import pytest

from raiden.api.python import RaidenAPI
from raiden.messages import DirectTransfer
from raiden.transfer import channel
from raiden.transfer.state import EMPTY_MERKLE_ROOT
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.factories import (
    UNIT_SECRETHASH,
    make_address,
    make_privkey_address,
)
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    get_channelstate,
    sign_and_inject,
)


@pytest.mark.skip(reason='direct_transfer_async doesnt return AsyncResult anymore')
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_failsfast_directtransfer_exceeding_distributable(
        raiden_network,
        token_addresses,
        deposit
):

    alice_app, bob_app = raiden_network
    token_address = token_addresses[0]

    async_result = alice_app.raiden.direct_transfer_async(
        token_address,
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
    channel0 = get_channelstate(app0, app1, token_address)

    identifier = 1
    invalid_token_address = make_address()
    channel_identifier = channel0.identifier
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=1,
        token=invalid_token_address,
        channel=channel_identifier,
        transferred_amount=0,
        recipient=app1.raiden.address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    sign_and_inject(
        direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidlocksroot(raiden_network, token_addresses):
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    channel0 = get_channelstate(app0, app1, token_address)
    balance0 = channel.get_balance(channel0.our_state, channel0.partner_state)
    balance1 = channel.get_balance(channel0.partner_state, channel0.our_state)

    identifier = 1
    invalid_locksroot = UNIT_SECRETHASH
    channel_identifier = channel0.identifier
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=1,
        token=token_address,
        channel=channel_identifier,
        transferred_amount=0,
        recipient=app1.raiden.address,
        locksroot=invalid_locksroot,
    )

    sign_and_inject(
        direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synched_channel_state(
        token_address,
        app0, balance0, [],
        app1, balance1, []
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidsender(raiden_network, deposit, token_addresses):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    other_key, other_address = make_privkey_address()

    channel0 = get_channelstate(app0, app1, token_address)
    channel_identifier = channel0.identifier
    direct_transfer_message = DirectTransfer(
        identifier=1,
        nonce=1,
        token=token_address,
        channel=channel_identifier,
        transferred_amount=10,
        recipient=app0.raiden.address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    sign_and_inject(
        direct_transfer_message,
        other_key,
        other_address,
        app0,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, []
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidnonce(raiden_network, deposit, token_addresses):

    app0, app1 = raiden_network
    token_address = token_addresses[0]
    channel0 = get_channelstate(app0, app1, token_address)

    transferred_amount = 10
    same_identifier = 1
    event = channel.send_directtransfer(
        channel0,
        transferred_amount,
        same_identifier,
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
    invalid_direct_transfer_message = DirectTransfer(
        identifier=same_identifier,
        nonce=1,
        token=token_address,
        channel=channel0.identifier,
        transferred_amount=invalid_transferred_amount,
        recipient=app1.raiden.address,
        locksroot=EMPTY_MERKLE_ROOT,
    )

    sign_and_inject(
        invalid_direct_transfer_message,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit - transferred_amount, [],
        app1, deposit + transferred_amount, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [30])
def test_received_directtransfer_closedchannel(raiden_network, token_addresses, deposit):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    channel0 = get_channelstate(app0, app1, token_address)

    RaidenAPI(app1.raiden).channel_close(
        token_address,
        app0.raiden.address,
    )

    wait_until_block(
        app0.raiden.chain,
        app0.raiden.chain.block_number() + 1,
    )

    # Now receive one direct transfer for the closed channel
    direct_transfer_message = DirectTransfer(
        identifier=1,
        nonce=1,
        token=token_address,
        channel=channel0.identifier,
        transferred_amount=10,
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
    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, [],
    )
