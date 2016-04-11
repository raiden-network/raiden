# -*- coding: utf8 -*-
from __future__ import print_function

import gevent
import pytest
from ethereum import slogging

from raiden.tests.utils import create_network, create_chain_network
from raiden.messages import decode, Ack, DirectTransfer, CancelTransfer
from raiden.tasks import MediatedTransferTask
from raiden.utils import pex
from raiden.tests.utils import setup_messages_cb, MessageLogger

# pylint: disable=too-many-locals,too-many-statements,line-too-long
slogging.configure(':debug')

# set shorter timeout for testing
MediatedTransferTask.timeout_per_hop = 0.1


def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()
    mlogger = MessageLogger()

    # channels
    asset_manager0 = app0.raiden.assetmanagers.values()[0]
    asset_manager1 = app1.raiden.assetmanagers.values()[0]

    assert asset_manager0.asset_address == asset_manager1.asset_address

    channel0 = asset_manager0.channels[app1.raiden.address]
    channel1 = asset_manager1.channels[app0.raiden.address]

    our_state0 = channel0.our_state
    our_state1 = channel1.our_state

    partner_state0 = channel0.partner_state
    partner_state1 = channel1.partner_state

    balance0 = our_state0.balance
    balance1 = our_state1.balance

    amount = 10
    target = app1.raiden.address
    assert target in asset_manager0.channels
    app0.raiden.api.transfer(asset_manager0.asset_address, amount, target=target)

    gevent.sleep(1)

    assert len(messages) == 2  # DirectTransfer, Ack
    direct_transfer = decode(messages[0])
    assert isinstance(direct_transfer, DirectTransfer)
    assert direct_transfer.balance == balance1 + amount

    ack = decode(messages[1])
    assert isinstance(ack, Ack)
    assert ack.echo == direct_transfer.hash

    assert balance1 + amount == our_state1.balance
    assert balance0 - amount == our_state0.balance

    assert our_state0.locked.root == ''
    assert our_state1.locked.root == ''
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root

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
    assert isinstance(a1_messages[0], Ack)
    assert isinstance(a1_messages[1], DirectTransfer)

    a1_sent_messages = mlogger.get_node_messages(a1_address, only='sent')
    assert len(a1_sent_messages) == 1
    assert isinstance(a1_sent_messages[0], Ack)

    a1_recv_messages = mlogger.get_node_messages(a1_address, only='recv')
    assert len(a1_recv_messages) == 1
    assert isinstance(a1_recv_messages[0], DirectTransfer)


def test_mediated_transfer():
    app_list = create_network(num_nodes=10, num_assets=1, channels_per_node=2)
    app0 = app_list[0]
    setup_messages_cb()

    # channels
    am0 = app0.raiden.assetmanagers.values()[0]

    # search for a path of length=2 A > B > C
    num_hops = 2
    source = app0.raiden.address

    path_list = am0.channelgraph.get_paths_of_length(source, num_hops)
    assert len(path_list)

    for path in path_list:
        assert len(path) == num_hops + 1
        assert path[0] == source

    path = path_list[0]
    target = path[-1]
    assert path in am0.channelgraph.get_shortest_paths(source, target)
    assert min(len(p) for p in am0.channelgraph.get_shortest_paths(source, target)) == num_hops + 1

    ams_by_address = dict(
        (app.raiden.address, app.raiden.assetmanagers)
        for app in app_list
    )

    # addresses
    hop1, hop2, hop3 = path

    # asset
    asset_address = am0.asset_address

    # channels
    c_ab = ams_by_address[hop1][asset_address].channels[hop2]
    c_ba = ams_by_address[hop2][asset_address].channels[hop1]
    c_bc = ams_by_address[hop2][asset_address].channels[hop3]
    c_cb = ams_by_address[hop3][asset_address].channels[hop2]

    # initial channel balances
    b_ab = c_ab.our_state.balance
    b_ba = c_ba.our_state.balance
    b_bc = c_bc.our_state.balance
    b_cb = c_cb.our_state.balance

    amount = 10

    app0.raiden.api.transfer(asset_address, amount, target)

    gevent.sleep(1.)

    # check
    assert b_ab - amount == c_ab.our_state.balance
    assert b_ba + amount == c_ba.our_state.balance
    assert b_bc - amount == c_bc.our_state.balance
    assert b_cb + amount == c_cb.our_state.balance


@pytest.skip
def test_cancel_transfer():
    app_list = create_chain_network(num_hops=3, deposit=100)
    app0, app1, app2 = app_list  # pylint: disable=unbalanced-tuple-unpacking

    asset_address = app0.raiden.assetmanagers.keys()[0]

    messages = setup_messages_cb()
    mlogger = MessageLogger()

    app1.raiden.api.transfer(asset_address, 80, app2.raiden.address)  # drain the channel
    gevent.sleep(1.)

    # save state
    asset_manager0 = app0.raiden.assetmanagers.values()[0]
    asset_manager1 = app1.raiden.assetmanagers.values()[0]
    channel0 = asset_manager0.channels[app1.raiden.address]
    channel1 = asset_manager1.channels[app0.raiden.address]
    our_state0 = channel0.our_state
    our_state1 = channel1.our_state
    partner_state0 = channel0.partner_state
    partner_state1 = channel1.partner_state
    balance0 = our_state0.balance
    balance1 = our_state1.balance

    app0.raiden.api.transfer(asset_address, 50, app2.raiden.address)  # test CancelTransfer
    gevent.sleep(1.)

    # check balances
    assert our_state0.balance == balance0
    assert our_state1.balance == balance1
    assert our_state0.distributable(partner_state0) == our_state0.balance
    assert our_state1.distributable(partner_state1) == our_state1.balance
    assert our_state0.locked.outstanding == 0
    assert our_state1.locked.outstanding == 0
    assert our_state0.locked.root == ''
    assert our_state1.locked.root == ''

    # check hashlock are empty
    assert len(our_state0.locked) == 0
    assert len(our_state1.locked) == 0
    assert len(partner_state0.locked) == 0
    assert len(partner_state1.locked) == 0

    # check the mirrors
    assert our_state0.balance == partner_state1.balance
    assert our_state1.balance == partner_state0.balance
    assert our_state0.locked.outstanding == partner_state1.locked.outstanding
    assert our_state1.locked.outstanding == partner_state0.locked.outstanding
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root
    assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
    assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)

    assert len(messages) == 6  # DirectTransfer + MediatedTransfer + CancelTransfer + a Ack for each

    app1_messages = mlogger.get_node_messages(pex(app1.raiden.address), only='sent')

    assert isinstance(app1_messages[-1], CancelTransfer)


if __name__ == '__main__':
    test_transfer()
    test_mediated_transfer()
