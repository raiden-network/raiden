from raiden.messages import Ack, deserialize, Transfer
from raiden.app import create_network
from .utils import setup_messages_cb, dump_messages
from raiden.tasks import TransferTask
import gevent


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

    apps = create_network(num_nodes=10, num_assets=1, channels_per_node=2)
    a0 = apps[0]
    messages = setup_messages_cb(a0.transport)

    # channels
    am0 = a0.raiden.assetmanagers.values()[0]

    # search for a path of length=2 A > B > C
    num_hops = 2
    source = a0.raiden.address
    paths = am0.channelgraph.get_paths_of_length(source, num_hops)
    assert len(paths)
    for p in paths:
        assert len(p) == num_hops + 1
        assert p[0] == source
    path = paths[0]
    target = path[-1]
    assert path in am0.channelgraph.get_paths(source, target)
    assert min(len(p) for p in am0.channelgraph.get_paths(source, target)) == num_hops + 1

    amount = 10
    # set shorter timeout for testing
    TransferTask.timeout_per_hop = 0.1

    asset_address = am0.asset_address
    a0.raiden.api.transfer(asset_address, amount, target)

    gevent.sleep(1.)
    # try:
    #     a0.raiden.api.transfer(asset_address, amount, target)
    # except Exception as e:
    #     dump_messages(messages)
    #     raise e

    # am1 = a1.raiden.assetmanagers.values()[0]

    # assert am0.asset_address == am1.asset_address

    # c0 = am0.channels[a1.raiden.address]
    # c1 = am1.channels[a0.raiden.address]

    # b0 = c0.balance
    # b1 = c1.balance

    # amount = 10
    # target = a1.raiden.address
    # assert target in am0.channels
    # a0.raiden.api.transfer(am0.asset_address, amount, target=target)

    # assert len(messages) == 2  # Transfer, Ack
    # mt = deserialize(messages[0])
    # assert isinstance(mt, Transfer)
    # assert mt.balance == b1 + amount
    # ma = deserialize(messages[1])
    # assert isinstance(ma, Ack)
    # assert ma.echo == mt.hash

    # assert b1 + amount == c1.balance
    # assert b0 - amount == c0.balance

    # assert c0.locked.root == c1.partner.locked.root == c1.locked.root == ''
