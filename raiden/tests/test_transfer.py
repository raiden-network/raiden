# -*- coding: utf8 -*-
import gevent

from ethereum import slogging

from raiden.app import create_network
from raiden.messages import Ack, decode, DirectTransfer
from raiden.tasks import TransferTask
from raiden.utils import pex
from raiden.tests.utils import setup_messages_cb, MessageLogger

slogging.configure(':debug')


def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    print('app0: {}'.format(pex(app0.raiden.address)))
    print('app1: {}'.format(pex(app1.raiden.address)))

    messages = setup_messages_cb()
    mlogger = MessageLogger()

    # channels
    am0 = app0.raiden.assetmanagers.values()[0]
    am1 = app1.raiden.assetmanagers.values()[0]

    assert am0.asset_address == am1.asset_address

    c0 = am0.channels[app1.raiden.address]
    c1 = am1.channels[app0.raiden.address]

    b0 = c0.balance
    b1 = c1.balance

    amount = 10
    target = app1.raiden.address
    assert target in am0.channels
    app0.raiden.api.transfer(am0.asset_address, amount, target=target)

    gevent.sleep(1)

    assert len(messages) == 2  # DirectTransfer, Ack
    mt = decode(messages[0])
    assert isinstance(mt, DirectTransfer)
    assert mt.balance == b1 + amount
    ma = decode(messages[1])
    assert isinstance(ma, Ack)
    assert ma.echo == mt.hash

    assert b1 + amount == c1.balance
    assert b0 - amount == c0.balance

    assert c0.locked.root == c1.partner.locked.root == c1.locked.root == ''

    a0_address = pex(app0.raiden.address)
    a1_address = pex(app1.raiden.address)

    a0_messages = mlogger.get_node_messages(a0_address)
    assert len(a0_messages) == 2
    assert isinstance(a0_messages[0], DirectTransfer)
    assert isinstance(a0_messages[1], Ack)

    a0_sent_messages = mlogger.get_node_messages(a0_address, only='sent')
    assert len(a0_sent_messages) == 1
    assert isinstance(a0_sent_messages[0], DirectTransfer)

    a0_recv_messages = mlogger.get_node_messages(a0_address, only='recv')
    assert len(a0_recv_messages) == 1
    assert isinstance(a0_recv_messages[0], Ack)

    a1_messages = mlogger.get_node_messages(a1_address)
    assert len(a1_messages) == 2
    assert isinstance(a1_messages[0], DirectTransfer)
    assert isinstance(a1_messages[1], Ack)

    a1_sent_messages = mlogger.get_node_messages(a1_address, only='sent')
    assert len(a1_sent_messages) == 1
    assert isinstance(a1_sent_messages[0], Ack)

    a1_recv_messages = mlogger.get_node_messages(a1_address, only='recv')
    assert len(a1_recv_messages) == 1
    assert isinstance(a1_recv_messages[0], DirectTransfer)


def test_mediated_transfer():

    apps = create_network(num_nodes=10, num_assets=1, channels_per_node=2)
    app0 = apps[0]
    setup_messages_cb()

    # channels
    am0 = app0.raiden.assetmanagers.values()[0]

    # search for a path of length=2 A > B > C
    num_hops = 2
    source = app0.raiden.address
    paths = am0.channelgraph.get_paths_of_length(source, num_hops)
    assert len(paths)
    for p in paths:
        assert len(p) == num_hops + 1
        assert p[0] == source
    path = paths[0]
    target = path[-1]
    assert path in am0.channelgraph.get_paths(source, target)
    assert min(len(p) for p in am0.channelgraph.get_paths(source, target)) == num_hops + 1

    ams_by_address = dict((a.raiden.address, a.raiden.assetmanagers) for a in apps)

    # addresses
    a, b, c = path

    # asset
    asset_address = am0.asset_address

    # channels
    c_ab = ams_by_address[a][asset_address].channels[b]
    c_ba = ams_by_address[b][asset_address].channels[a]
    c_bc = ams_by_address[b][asset_address].channels[c]
    c_cb = ams_by_address[c][asset_address].channels[b]

    # initial channel balances
    b_ab = c_ab.balance
    b_ba = c_ba.balance
    b_bc = c_bc.balance
    b_cb = c_cb.balance

    amount = 10
    # set shorter timeout for testing
    TransferTask.timeout_per_hop = 0.1

    app0.raiden.api.transfer(asset_address, amount, target)

    gevent.sleep(1.)

    # check
    assert b_ab - amount == c_ab.balance
    assert b_ba + amount == c_ba.balance
    assert b_bc - amount == c_bc.balance
    assert b_cb + amount == c_cb.balance


if __name__ == '__main__':
    test_transfer()
    test_mediated_transfer()
