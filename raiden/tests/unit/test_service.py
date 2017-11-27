# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.utils import sha3
from raiden.api.python import RaidenAPI
from raiden.messages import (
    decode,
    Ack,
    Ping,
)
from raiden.tests.utils.transport import UnreliableTransport
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.transfer import channel
from raiden.tests.fixtures.raiden_network import CHAIN


@pytest.mark.parametrize('number_of_nodes', [2])
def test_ping(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()

    ping_message = Ping(nonce=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    async_result = app0.raiden.protocol.send_raw_with_result(
        ping_encoded,
        app1.raiden.address,
    )
    assert async_result.wait(2), 'The message was not acknowledged'

    expected_echohash = sha3(ping_encoded + app1.raiden.address)

    messages_decoded = [decode(m) for m in messages]
    ack_message = next(
        decoded
        for decoded in messages_decoded
        if isinstance(decoded, Ack) and decoded.echo == expected_echohash
    )

    # the ping message was sent and acknowledged
    assert ping_encoded in messages
    assert ack_message


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_ping_unreachable(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # drop everything to force disabling of re-sends
    app0.raiden.protocol.transport.droprate = 1
    app1.raiden.protocol.transport.droprate = 1

    app0.raiden.protocol.retry_interval = 0.1  # for fast tests

    messages = setup_messages_cb()

    ping_message = Ping(nonce=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    async_result = app0.raiden.protocol.send_raw_with_result(
        ping_encoded,
        app1.raiden.address,
    )

    assert async_result.wait(2) is None, "The message was dropped, it can't be acknowledged"

    # Raiden node will start pinging as soon as a new channel
    #  is established. We need to test if
    #  a) there is our original message in the queue
    #  b) there are only Ping message types in
    messages_decoded = [decode(m) for m in messages]
    assert ping_message in messages_decoded
    for message in messages_decoded:
        assert isinstance(message, Ping)


@pytest.mark.parametrize('deposit', [0])
def test_receive_direct_before_deposit(raiden_network):
    """Regression test that ensures we accept incoming direct transfers, even if we don't have
    any back channel balance.  """
    app0, app1, _ = raiden_network

    token_address = app0.raiden.default_registry.token_addresses()[0]
    channel_0_1 = channel(app0, app1, token_address)
    back_channel = channel(app1, app0, token_address)

    assert not channel_0_1.can_transfer
    assert not back_channel.can_transfer

    deposit_amount = 2
    transfer_amount = 1
    api0 = RaidenAPI(app0.raiden)
    api0.deposit(token_address, app1.raiden.address, deposit_amount)
    app0.raiden.chain.next_block()
    gevent.sleep(app0.raiden.alarm.wait_time)

    assert channel_0_1.can_transfer
    assert not back_channel.can_transfer
    assert back_channel.distributable == 0

    api0.transfer_and_wait(token_address, transfer_amount, app1.raiden.address)
    gevent.sleep(app1.raiden.alarm.wait_time)

    assert back_channel.can_transfer
    assert back_channel.distributable == transfer_amount


@pytest.mark.parametrize('deposit', [0])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_receive_mediated_before_deposit(raiden_network, token_addresses):
    """Regression test that ensures we accept incoming mediated transfers, even if we don't have
    any back channel balance. """
    app_alice, app_bob, app_charlie = raiden_network
    token_address = token_addresses[0]

    # path alice -> bob -> charlie
    alice_bob = channel(app_alice, app_bob, token_address)
    bob_alice = channel(app_bob, app_alice, token_address)
    bob_charlie = channel(app_bob, app_charlie, token_address)
    charlie_bob = channel(app_charlie, app_bob, token_address)

    # ensure alice charlie is mediated
    with pytest.raises(KeyError):
        channel(app_alice, app_charlie, token_address)

    assert not alice_bob.can_transfer
    assert not bob_charlie.can_transfer
    assert not bob_alice.can_transfer

    deposit_amount = 3
    RaidenAPI(app_alice.raiden).deposit(
        token_address,
        app_bob.raiden.address,
        deposit_amount,
    )

    RaidenAPI(app_bob.raiden).deposit(
        token_address,
        app_charlie.raiden.address,
        deposit_amount,
    )

    # catch up with the Balance events
    for app in raiden_network:
        app.raiden.poll_blockchain_events()

    assert alice_bob.can_transfer
    assert bob_charlie.can_transfer
    assert not bob_alice.can_transfer

    assert alice_bob.distributable == deposit_amount
    assert bob_charlie.distributable == deposit_amount

    transfer_amount = 1
    async_result = app_alice.raiden.mediated_transfer_async(
        token_address,
        transfer_amount,
        app_charlie.raiden.address,
        1,
    )
    assert async_result.wait(10)

    # give extra time for the intermediaries to process the secret messages and
    # withdraw the tokens
    gevent.sleep(1)

    assert alice_bob.distributable == deposit_amount - transfer_amount
    assert bob_charlie.distributable == deposit_amount - transfer_amount
    assert bob_alice.distributable == transfer_amount
    assert charlie_bob.distributable == transfer_amount

    assert alice_bob.can_transfer
    assert bob_alice.can_transfer
    assert charlie_bob.can_transfer
