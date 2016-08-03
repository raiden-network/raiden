# -*- coding: utf8 -*-
from __future__ import print_function

import gevent
import pytest
from ethereum import slogging

from raiden.messages import decode, Ack, DirectTransfer, RefundTransfer
from raiden.tests.utils.messages import setup_messages_cb, MessageLogger
from raiden.tests.utils.transfer import assert_synched_channels, channel, direct_transfer, transfer
from raiden.tests.utils.network import CHAIN
from raiden.utils import pex, sha3

# pylint: disable=too-many-locals,too-many-statements,line-too-long
slogging.configure(':DEBUG')

from pyethapp.utils import enable_greenlet_debugger
enable_greenlet_debugger()


@pytest.mark.parametrize('privatekey_seed', ['transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_transfer(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()
    mlogger = MessageLogger()

    a0_address = pex(app0.raiden.address)
    a1_address = pex(app1.raiden.address)

    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]
    asset_manager1 = app1.raiden.managers_by_asset_address.values()[0]

    channel0 = asset_manager0.partneraddress_channel[app1.raiden.address]
    channel1 = asset_manager1.partneraddress_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert app1.raiden.address in asset_manager0.partneraddress_channel

    amount = 10
    app0.raiden.api.transfer(
        asset_manager0.asset_address,
        amount,
        target=app1.raiden.address,
    )
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    assert len(messages) == 2  # DirectTransfer, Ack
    directtransfer_message = decode(messages[0])
    assert isinstance(directtransfer_message, DirectTransfer)
    assert directtransfer_message.transfered_amount == amount

    ack_message = decode(messages[1])
    assert isinstance(ack_message, Ack)
    assert ack_message.echo == directtransfer_message.hash

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


@pytest.mark.parametrize('privatekey_seed', ['mediated_transfer:{}'])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('number_of_nodes', [10])
def test_mediated_transfer(raiden_network):
    app0 = raiden_network[0]
    setup_messages_cb()

    am0 = app0.raiden.managers_by_asset_address.values()[0]

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
        (app.raiden.address, app.raiden.managers_by_asset_address)
        for app in raiden_network
    )

    # addresses
    hop1, hop2, hop3 = path

    # asset
    asset_address = am0.asset_address

    # channels
    c_ab = ams_by_address[hop1][asset_address].partneraddress_channel[hop2]
    c_ba = ams_by_address[hop2][asset_address].partneraddress_channel[hop1]
    c_bc = ams_by_address[hop2][asset_address].partneraddress_channel[hop3]
    c_cb = ams_by_address[hop3][asset_address].partneraddress_channel[hop2]

    # initial channel balances
    b_ab = c_ab.balance
    b_ba = c_ba.balance
    b_bc = c_bc.balance
    b_cb = c_cb.balance

    amount = 10

    app0.raiden.api.transfer(asset_address, amount, target)

    gevent.sleep(1.)

    # check
    assert b_ab - amount == c_ab.balance
    assert b_ba + amount == c_ba.balance
    assert b_bc - amount == c_bc.balance
    assert b_cb + amount == c_cb.balance


@pytest.mark.xfail(reason='MediatedTransfer doesnt yet update balances on Refund')
@pytest.mark.parametrize('privatekey_seed', ['cancel_transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('asset', [sha3('cancel_transfer')[:20]])
@pytest.mark.parametrize('deposit', [100])
def test_cancel_transfer(raiden_chain, asset, deposit):

    app0, app1, app2, app3 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()
    mlogger = MessageLogger()

    assert_synched_channels(
        channel(app0, app1, asset), deposit, [],
        channel(app1, app0, asset), deposit, []
    )

    assert_synched_channels(
        channel(app1, app2, asset), deposit, [],
        channel(app2, app1, asset), deposit, []
    )

    assert_synched_channels(
        channel(app2, app3, asset), deposit, [],
        channel(app3, app2, asset), deposit, []
    )

    assert_synched_channels(
        channel(app0, app1, asset), deposit, [],
        channel(app1, app0, asset), deposit, []
    )

    # drain the channel app1 -> app2
    amount12 = 50
    direct_transfer(app1, app2, asset, amount12)

    # drain the channel app2 -> app3
    amount23 = 80
    direct_transfer(app2, app3, asset, amount23)

    assert_synched_channels(
        channel(app1, app2, asset), deposit - amount12, [],
        channel(app2, app1, asset), deposit + amount12, []
    )

    assert_synched_channels(
        channel(app2, app3, asset), deposit - amount23, [],
        channel(app3, app2, asset), deposit + amount23, []
    )

    # app1 -> app3 is the only available path but app2 -> app3 doesnt have
    # resources and needs to send a RefundTransfer down the path
    transfer(app0, app3, asset, 50)

    assert_synched_channels(
        channel(app0, app1, asset), deposit, [],
        channel(app1, app0, asset), deposit, []
    )

    # FIXME
    assert_synched_channels(
        channel(app1, app2, asset), deposit - amount12, [],
        channel(app2, app1, asset), deposit + amount12, []
    )

    assert_synched_channels(
        channel(app2, app3, asset), deposit - amount23, [],
        channel(app3, app2, asset), deposit + amount23, []
    )

    assert len(messages) == 12  # DT + DT + SMT + MT + RT + RT + ACKs

    app1_messages = mlogger.get_node_messages(pex(app1.raiden.address), only='sent')
    assert isinstance(app1_messages[-1], RefundTransfer)

    app2_messages = mlogger.get_node_messages(pex(app2.raiden.address), only='sent')
    assert isinstance(app2_messages[-1], RefundTransfer)
