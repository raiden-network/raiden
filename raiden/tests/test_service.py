from raiden.messages import Ping, Ack, deserialize, Transfer
from raiden.app import create_network
from raiden.transport import UnreliableTransport
from raiden.raiden_service import RaidenProtocol


def setup_messages_cb(transport):
    messages = []

    def cb(sender_raiden, host_port, msg):
        messages.append(msg)
    transport.on_send_cbs = [cb]
    return messages


def test_ping():
    apps = create_network(num_nodes=2, num_assets=0, channels_per_node=0)
    a0, a1 = apps
    messages = setup_messages_cb(a0.transport)
    p = Ping(nonce=0).sign(a0.raiden.address)
    a0.raiden.protocol.send(a1.raiden.address, p)
    assert len(messages) == 2  # Ping, Ack
    assert deserialize(messages[0]) == p
    a = deserialize(messages[1])
    assert isinstance(a, Ack)
    assert a.echo == p.hash


def test_ping_dropped_message():
    apps = create_network(num_nodes=2, num_assets=0, channels_per_node=0)
    a0, a1 = apps

    # mock transport with packet loss, every 3nd is lost, starting with first message
    UnreliableTransport.droprate = 3
    RaidenProtocol.try_interval = 0.1  # for fast tests
    a0.transport.__class__ = UnreliableTransport
    a1.transport.__class__ = UnreliableTransport

    messages = setup_messages_cb(a0.transport)

    p = Ping(nonce=0).sign(a0.raiden.address)
    a0.raiden.protocol.send(a1.raiden.address, p)

    assert len(messages) == 3  # Ping(dropped), Ping, Ack
    for i in [0, 1]:
        assert deserialize(messages[i]) == p
    for i in [2]:
        a = deserialize(messages[i])
        assert isinstance(a, Ack)
    assert a.echo == p.hash

    # try failing Ack
    messages = setup_messages_cb(a0.transport)

    a0.transport.counter = 2  # first message sent, 2nd dropped
    p = Ping(nonce=0).sign(a0.raiden.address)
    a0.raiden.protocol.send(a1.raiden.address, p)

    for m in messages:
        print deserialize(m)

    assert len(messages) == 4  # Ping, Ack(dropped), Ping, Ack
    for i in [0, 2]:
        assert deserialize(messages[i]) == p
    for i in [1, 3]:
        a = deserialize(messages[i])
        assert isinstance(a, Ack)
    assert a.echo == p.hash


def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    messages = setup_messages_cb(a0.transport)

    # channels
    am0 = a0.raiden.assetmanagers.values()[0]
    am1 = a1.raiden.assetmanagers.values()[0]

    assert am0.asset_address == am1.asset_address

    c0 = am0.channels[a1.raiden.address]
    c1 = am1.channels[a0.raiden.address]

    b0 = c0.balance
    b1 = c1.balance

    amount = 10
    target = a1.raiden.address
    assert target in am0.channels
    a0.raiden.api.transfer(am0.asset_address, amount, target=target)

    assert len(messages) == 2  # Transfer, Ack
    mt = deserialize(messages[0])
    assert isinstance(mt, Transfer)
    assert mt.balance == b1 + amount
    ma = deserialize(messages[1])
    assert isinstance(ma, Ack)
    assert ma.echo == mt.hash

    assert b1 + amount == c1.balance
    assert b0 - amount == c0.balance

    assert c0.locked.root == c1.partner.locked.root == c1.locked.root == ''


def test_mediated_transfer():
    pass
