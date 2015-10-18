from raiden.messages import Ping, Ack, decode
from raiden.app import create_network
from raiden.transport import UnreliableTransport
from raiden.raiden_protocol import RaidenProtocol
from .utils import setup_messages_cb
import gevent


def test_ping():
    apps = create_network(num_nodes=2, num_assets=0, channels_per_node=0)
    a0, a1 = apps
    messages = setup_messages_cb()
    p = Ping(nonce=0)
    a0.raiden.sign(p)
    a0.raiden.protocol.send(a1.raiden.address, p)
    gevent.sleep(0.1)
    assert len(messages) == 2  # Ping, Ack
    assert decode(messages[0]) == p
    a = decode(messages[1])
    assert isinstance(a, Ack)
    assert a.echo == p.hash


def test_ping_dropped_message():
    apps = create_network(num_nodes=2, num_assets=0, channels_per_node=0)
    a0, a1 = apps

    # mock transport with packet loss, every 3nd is lost, starting with first message
    UnreliableTransport.droprate = 3
    RaidenProtocol.try_interval = 0.1  # for fast tests
    RaidenProtocol.repeat_messages = True
    a0.transport.__class__ = UnreliableTransport
    a1.transport.__class__ = UnreliableTransport

    messages = setup_messages_cb()
    UnreliableTransport.network.counter = 0

    p = Ping(nonce=0)
    a0.raiden.sign(p)
    a0.raiden.protocol.send(a1.raiden.address, p)
    gevent.sleep(1)

    assert len(messages) == 3  # Ping(dropped), Ping, Ack
    for i in [0, 1]:
        assert decode(messages[i]) == p
    for i in [2]:
        a = decode(messages[i])
        assert isinstance(a, Ack)
    assert a.echo == p.hash

    # try failing Ack
    messages = setup_messages_cb()
    assert not messages

    UnreliableTransport.network.counter = 2  # first message sent, 2nd dropped
    p = Ping(nonce=0)
    a0.raiden.sign(p)
    a0.raiden.protocol.send(a1.raiden.address, p)
    gevent.sleep(1)

    for m in messages:
        print decode(m)

    assert len(messages) == 4  # Ping, Ack(dropped), Ping, Ack
    for i in [0, 2]:
        assert decode(messages[i]) == p
    for i in [1, 3]:
        a = decode(messages[i])
        assert isinstance(a, Ack)
    assert a.echo == p.hash

    RaidenProtocol.repeat_messages = False
