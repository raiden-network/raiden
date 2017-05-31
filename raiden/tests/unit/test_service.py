# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.utils import sha3
from raiden.api.python import RaidenAPI
from raiden.messages import Ping, Ack, decode
from raiden.network.transport import UnreliableTransport, UDPTransport, RaidenProtocol
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.transfer import channel


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_ping(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()
    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send_and_wait(app1.raiden.address, ping)
    gevent.sleep(0.1)
    assert len(messages) == 2  # Ping, Ack
    assert decode(messages[0]) == ping
    decoded = decode(messages[1])
    assert isinstance(decoded, Ack)
    assert decoded.echo == sha3(ping.encode() + app1.raiden.address)


@pytest.mark.timeout(5)
@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_ping_unreachable(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    UnreliableTransport.droprate = 1  # drop everything to force disabling of re-sends
    RaidenProtocol.try_interval = 0.1  # for fast tests
    RaidenProtocol.repeat_messages = True

    messages = setup_messages_cb()
    UnreliableTransport.network.counter = 0

    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send_and_wait(app1.raiden.address, ping)
    gevent.sleep(2)

    assert len(messages) == 5  # 5 dropped Pings
    for message in messages:
        assert decode(message) == ping

    RaidenProtocol.repeat_messages = False


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_ping_dropped_message(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # mock transport with packet loss, every 3rd is lost, starting with first message
    UnreliableTransport.droprate = 3
    RaidenProtocol.try_interval = 0.1  # for fast tests
    RaidenProtocol.repeat_messages = True

    messages = setup_messages_cb()
    UnreliableTransport.network.counter = 0

    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send_and_wait(app1.raiden.address, ping)
    gevent.sleep(1)

    assert len(messages) == 3  # Ping(dropped), Ping, Ack

    for i in [0, 1]:
        assert decode(messages[i]) == ping

    for i in [2]:
        decoded = decode(messages[i])
        assert isinstance(decoded, Ack)

    assert decoded.echo == sha3(ping.encode() + app1.raiden.address)

    messages = setup_messages_cb()
    assert not messages

    UnreliableTransport.network.counter = 2  # first message sent, 2nd dropped
    ping = Ping(nonce=1)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send_and_wait(app1.raiden.address, ping)
    gevent.sleep(1)

    assert len(messages) == 4  # Ping, Ack(dropped), Ping, Ack
    for i in [0, 2]:
        assert decode(messages[i]) == ping
    for i in [1, 3]:
        decoded = decode(messages[i])
        assert isinstance(decoded, Ack)
    assert decoded.echo == sha3(ping.encode() + app1.raiden.address)

    RaidenProtocol.repeat_messages = False


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UDPTransport])
def test_ping_udp(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    messages = setup_messages_cb()
    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send_and_wait(app1.raiden.address, ping)
    gevent.sleep(0.1)
    assert len(messages) == 2  # Ping, Ack
    assert decode(messages[0]) == ping
    decoded = decode(messages[1])
    assert isinstance(decoded, Ack)
    assert decoded.echo == sha3(ping.encode() + app1.raiden.address)


@pytest.mark.parametrize('privatekey_seed', ['ping_dropped_message:{}'])
@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_ping_ordering(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # mock transport with packet loss, every 3rd is lost, starting with first message
    droprate = UnreliableTransport.droprate = 3
    RaidenProtocol.try_interval = 0.1  # for fast tests
    RaidenProtocol.repeat_messages = True

    messages = setup_messages_cb()
    UnreliableTransport.network.counter = 0

    ping_amount = 5

    hashes = []
    for nonce in range(ping_amount):
        ping = Ping(nonce=nonce)
        app0.raiden.sign(ping)
        app0.raiden.protocol.send_and_wait(app1.raiden.address, ping)
        pinghash = sha3(ping.encode() + app1.raiden.address)
        hashes.append(pinghash)

    gevent.sleep(2)  # give some time for messages to be handled

    expected_message_amount = ping_amount * droprate
    assert len(messages) == expected_message_amount

    for i in range(0, expected_message_amount, droprate):
        assert isinstance(decode(messages[i]), Ping)

    for i in range(1, expected_message_amount, droprate):
        assert isinstance(decode(messages[i]), Ping)

    for i, j in zip(range(2, expected_message_amount, droprate), range(ping_amount)):
        decoded = decode(messages[i])
        assert isinstance(decoded, Ack)
        assert decoded.echo == hashes[j]

    RaidenProtocol.repeat_messages = False


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('deposit', [0])
def test_receive_direct_before_deposit(raiden_network):
    """Regression test that ensures we accept incoming direct transfers, even if we don't have
    any back channel balance.  """
    app0, app1, app2 = raiden_network

    token_address = app0.raiden.chain.default_registry.token_addresses()[0]
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


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('deposit', [0])
def test_receive_mediated_before_deposit(raiden_network):
    """Regression test that ensures we accept incoming mediated transfers, even if we don't have
    any back channel balance. """
    app_bob, app_alice, app_charlie = raiden_network

    chain = app_bob.raiden.chain

    token_address = app_bob.raiden.chain.default_registry.token_addresses()[0]
    # path alice -> bob -> charlie
    alice_bob = channel(app_alice, app_bob, token_address)
    bob_alice = channel(app_bob, app_alice, token_address)
    bob_charlie = channel(app_bob, app_charlie, token_address)
    charlie_bob = channel(app_charlie, app_bob, token_address)

    all_channels = dict(
        alice_bob=alice_bob,
        bob_alice=bob_alice,
        bob_charlie=bob_charlie,
        charlie_bob=charlie_bob
    )
    # ensure alice charlie is mediated
    with pytest.raises(KeyError):
        channel(app_alice, app_charlie, token_address)

    assert not alice_bob.can_transfer
    assert not bob_charlie.can_transfer
    assert not bob_alice.can_transfer

    deposit_amount = 3
    transfer_amount = 1

    api_alice = RaidenAPI(app_alice.raiden)
    api_alice.deposit(token_address, app_bob.raiden.address, deposit_amount)
    chain.next_block()
    gevent.sleep(app_alice.raiden.alarm.wait_time)

    api_bob = RaidenAPI(app_bob.raiden)
    api_bob.deposit(token_address, app_charlie.raiden.address, deposit_amount)
    chain.next_block()
    gevent.sleep(app_bob.raiden.alarm.wait_time)

    assert alice_bob.can_transfer
    assert alice_bob.distributable == deposit_amount
    assert bob_charlie.can_transfer
    assert bob_charlie.distributable == deposit_amount
    assert not bob_alice.can_transfer

    api_alice.transfer_and_wait(token_address, transfer_amount, app_charlie.raiden.address)
    gevent.sleep(app_alice.raiden.alarm.wait_time)

    assert alice_bob.distributable == deposit_amount - transfer_amount
    assert bob_charlie.distributable == deposit_amount - transfer_amount
    assert bob_alice.distributable == transfer_amount, channel_balances(all_channels)
    assert bob_alice.can_transfer
    assert charlie_bob.distributable == transfer_amount, channel_balances(all_channels)
    assert charlie_bob.can_transfer


def channel_balances(name_to_channel):
    result = dict()
    for name, channel_ in name_to_channel.items():
        result[name] = dict(
            deposit=channel_.deposit,
            balance=channel_.balance,
            distributable=channel_.distributable,
            locked=channel_.locked
        )
    return result
