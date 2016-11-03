# -*- coding: utf-8 -*-
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


@pytest.mark.parametrize('blockchain_type', ['mock'])
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
    assert directtransfer_message.transferred_amount == amount

    ack_message = decode(messages[1])
    assert isinstance(ack_message, Ack)
    assert ack_message.echo == sha3(directtransfer_message.encode() + app1.raiden.address)

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


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('number_of_nodes', [10])
def test_mediated_transfer(raiden_network):

    def get_channel(from_, to_):
        return ams_by_address[from_][asset_address].partneraddress_channel[to_]

    alice_app = raiden_network[0]
    setup_messages_cb()

    asset_manager = alice_app.raiden.managers_by_asset_address.values()[0]
    asset_address = asset_manager.asset_address

    # search for a path of length=2 A > B > C
    num_hops = 2
    initiator_address = alice_app.raiden.address

    paths_length_2 = asset_manager.channelgraph.get_paths_of_length(
        initiator_address,
        num_hops,
    )

    assert len(paths_length_2)
    for path in paths_length_2:
        assert len(path) == num_hops + 1
        assert path[0] == initiator_address

    path = paths_length_2[0]

    alice_address, bob_address, charlie_address = path

    shortest_paths = list(asset_manager.channelgraph.get_shortest_paths(
        initiator_address,
        charlie_address,
    ))

    assert path in shortest_paths
    assert min(len(path) for path in shortest_paths) == num_hops + 1

    ams_by_address = dict(
        (app.raiden.address, app.raiden.managers_by_asset_address)
        for app in raiden_network
    )

    # channels (alice <-> bob <-> charlie)
    channel_ab = get_channel(alice_address, bob_address)
    channel_ba = get_channel(bob_address, alice_address)
    channel_bc = get_channel(bob_address, charlie_address)
    channel_cb = get_channel(charlie_address, bob_address)

    initial_balance_ab = channel_ab.balance
    initial_balance_ba = channel_ba.balance
    initial_balance_bc = channel_bc.balance
    initial_balance_cb = channel_cb.balance

    amount = 10

    alice_app.raiden.api.transfer(
        asset_address,
        amount,
        charlie_address,
    )

    gevent.sleep(1.)

    assert initial_balance_ab - amount == channel_ab.balance
    assert initial_balance_ba + amount == channel_ba.balance
    assert initial_balance_bc - amount == channel_bc.balance
    assert initial_balance_cb + amount == channel_cb.balance


@pytest.mark.xfail(reason='MediatedTransfer doesnt yet update balances on Refund')
@pytest.mark.parametrize('blockchain_type', ['mock'])
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
