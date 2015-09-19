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
