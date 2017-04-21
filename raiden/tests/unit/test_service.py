# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.utils import sha3
from raiden.messages import Ping, Ack, decode
from raiden.network.transport import UnreliableTransport, UDPTransport, RaidenProtocol
from raiden.tests.utils.messages import setup_messages_cb


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
