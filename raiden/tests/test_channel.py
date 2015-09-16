from raiden.messages import Ping, Ack, deserialize
from raiden.app import create_network, transport
from raiden.channel import Channel
from raiden.utils import activate_ultratb, pex, lpex
activate_ultratb()


def setup_messages_cb():
    messages = []

    def cb(sender_raiden, host_port, msg):
        messages.append(msg)
    transport.on_send_cbs = [cb]
    return messages


def test_setup():
    messages = setup_messages_cb()
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps

    s = a0.raiden.chain.channels_by_asset[a0.raiden.chain.asset_addresses[0]]
    assert s.channels
    assert s.channels_by_address(a0.raiden.address)

    assert a0.raiden.assets.keys() == a1.raiden.assets.keys()
    assert len(a0.raiden.assets) == 1


def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    c0 = a0.raiden.assets.values()[0].channels.values()[0]
    c1 = a1.raiden.assets.values()[0].channels.values()[0]

    assert c0.contract == c1.contract

    assert c0.balance == c0.distributable == c0.contract.participants[c0.address]['deposit']
    amount = 10
    assert amount < c0.distributable
    t = c0.create_transfer(amount=amount)
    c1.receive(t)

    # p = Ping(nonce=0).sign(a0.raiden.address)
    # a0.raiden.protocol.send(a1.raiden.address, p)
    # assert len(messages) == 2  # Ping, Ack
    # assert deserialize(messages[0]) == p
    # a = deserialize(messages[1])
    # assert isinstance(a, Ack)
    # assert a.echo == p.hash

if __name__ == '__main__':
    test_setup()
