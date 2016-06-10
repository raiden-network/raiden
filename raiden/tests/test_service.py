# -*- coding: utf8 -*-
import gevent

from ethereum import slogging

from raiden.messages import Ping, Ack, decode
from raiden.network.transport import UnreliableTransport, UDPTransport
from raiden.raiden_protocol import RaidenProtocol
from raiden.tests.utils.network import create_network
from raiden.tests.utils.messages import setup_messages_cb

slogging.configure(':debug')


def teardown_module(module):  # pylint: disable=unused-argument
    from raiden.tests.utils.tests import cleanup_tasks
    cleanup_tasks()


def test_ping():
    apps = create_network(num_nodes=2, num_assets=0, channels_per_node=0)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    messages = setup_messages_cb()
    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send(app1.raiden.address, ping)
    gevent.sleep(0.1)
    assert len(messages) == 2  # Ping, Ack
    assert decode(messages[0]) == ping
    decoded = decode(messages[1])
    assert isinstance(decoded, Ack)
    assert decoded.echo == ping.hash


def test_ping_dropped_message():
    apps = create_network(
        num_nodes=2,
        num_assets=0,
        channels_per_node=0,
        transport_class=UnreliableTransport,
    )
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    # mock transport with packet loss, every 3nd is lost, starting with first message
    UnreliableTransport.droprate = 3
    RaidenProtocol.try_interval = 0.1  # for fast tests
    RaidenProtocol.repeat_messages = True

    messages = setup_messages_cb()
    UnreliableTransport.network.counter = 0

    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send(app1.raiden.address, ping)
    gevent.sleep(1)

    assert len(messages) == 3  # Ping(dropped), Ping, Ack

    for i in [0, 1]:
        assert decode(messages[i]) == ping

    for i in [2]:
        decoded = decode(messages[i])
        assert isinstance(decoded, Ack)

    assert decoded.echo == ping.hash

    # try failing Ack
    messages = setup_messages_cb()
    assert not messages

    UnreliableTransport.network.counter = 2  # first message sent, 2nd dropped
    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send(app1.raiden.address, ping)
    gevent.sleep(1)

    for message in messages:
        print decode(message)

    assert len(messages) == 4  # Ping, Ack(dropped), Ping, Ack
    for i in [0, 2]:
        assert decode(messages[i]) == ping
    for i in [1, 3]:
        decoded = decode(messages[i])
        assert isinstance(decoded, Ack)
    assert decoded.echo == ping.hash

    RaidenProtocol.repeat_messages = False


def test_ping_udp():
    apps = create_network(
        num_nodes=2,
        num_assets=0,
        channels_per_node=0,
        transport_class=UDPTransport,
    )
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    messages = setup_messages_cb()
    ping = Ping(nonce=0)
    app0.raiden.sign(ping)
    app0.raiden.protocol.send(app1.raiden.address, ping)
    gevent.sleep(0.1)
    assert len(messages) == 2  # Ping, Ack
    assert decode(messages[0]) == ping
    decoded = decode(messages[1])
    assert isinstance(decoded, Ack)
    assert decoded.echo == ping.hash
