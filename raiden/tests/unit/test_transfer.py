# -*- coding: utf-8 -*-
from __future__ import print_function

import gevent
import pytest
from ethereum import slogging
from secp256k1 import PrivateKey

from raiden.encoding.signing import GLOBAL_CTX
from raiden.messages import (
    Ack,
    ConfirmTransfer,
    decode,
    DirectTransfer,
    Lock,
    MediatedTransfer,
    Ping,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
    TransferTimeout
)
from raiden.network.transport import UnreliableTransport
from raiden.tests.utils.messages import setup_messages_cb, MessageLogger
from raiden.tests.utils.transfer import assert_synched_channels, channel, direct_transfer, transfer
from raiden.tests.utils.network import CHAIN
from raiden.utils import pex, sha3, privatekey_to_address

# pylint: disable=too-many-locals,too-many-statements,line-too-long
slogging.configure(':DEBUG')

HASH = sha3("muchcodingsuchwow")


def sign_and_send(message, key, address, app):
    message.sign(key, address)
    message_data = str(message.packed().data)
    app.raiden.protocol.receive(message_data)
    # Give it some time to see if the unknown sender causes an error in the logic
    gevent.sleep(3)


class MediatedTransferTestHelper:

    def __init__(self, raiden_network, asset_manager):
        self.raiden_network = raiden_network
        self.asset_manager = asset_manager
        self.asset_address = asset_manager.asset_address
        self.ams_by_address = dict(
            (app.raiden.address, app.raiden.managers_by_asset_address)
            for app in self.raiden_network
        )

    def get_channel(self, from_, to_):
        return self.ams_by_address[from_][self.asset_address].partneraddress_channel[to_]

    def get_paths_of_length(self, initiator_address, num_hops):
        """
        Search for paths of length=num_of_hops starting from initiator_address
        """
        paths_length = self.asset_manager.channelgraph.get_paths_of_length(
            initiator_address,
            num_hops,
        )
        assert len(paths_length)
        for path in paths_length:
            assert len(path) == num_hops + 1
            assert path[0] == initiator_address
        return paths_length[0]

    def assert_path_in_shortest_paths(self, path, initiator_address, num_hops):
        _, _, charlie_address = path
        shortest_paths = list(self.asset_manager.channelgraph.get_shortest_paths(
            initiator_address,
            charlie_address,
        ))
        assert path in shortest_paths
        assert min(len(path) for path in shortest_paths) == num_hops + 1

    def get_app_from_address(self, address):
        for app in self.raiden_network:
            if address == app.raiden.address:
                return app
        return None



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
    alice_app = raiden_network[0]
    setup_messages_cb()

    asset_manager = alice_app.raiden.managers_by_asset_address.values()[0]
    asset_address = asset_manager.asset_address
    mt_helper = MediatedTransferTestHelper(raiden_network, asset_manager)

    initiator_address = alice_app.raiden.address
    path = mt_helper.get_paths_of_length(initiator_address, 2)
    mt_helper.assert_path_in_shortest_paths(path, initiator_address, 2)
    alice_address, bob_address, charlie_address = path

    # channels (alice <-> bob <-> charlie)
    channel_ab = mt_helper.get_channel(alice_address, bob_address)
    channel_ba = mt_helper.get_channel(bob_address, alice_address)
    channel_bc = mt_helper.get_channel(bob_address, charlie_address)
    channel_cb = mt_helper.get_channel(charlie_address, bob_address)

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


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('send_ping_time', [3])
@pytest.mark.parametrize('max_unresponsive_time', [6])
def test_healthcheck_with_normal_peer(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    messages = setup_messages_cb()

    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]
    asset_manager1 = app1.raiden.managers_by_asset_address.values()[0]

    max_unresponsive_time = app0.raiden.config['max_unresponsive_time']

    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert app1.raiden.address in asset_manager0.partneraddress_channel

    amount = 10
    app0.raiden.api.transfer(
        asset_manager0.asset_address,
        amount,
        target=app1.raiden.address,
    )

    gevent.sleep(max_unresponsive_time)
    assert asset_manager0.channelgraph.has_path(
        app0.raiden.address,
        app1.raiden.address
    )

    # At this point we should have sent a direct transfer and got back the ack
    # and gotten at least 1 ping - ack for a normal healthcheck
    assert len(messages) >= 4  # DirectTransfer, Ack, Ping, Ack
    assert isinstance(decode(messages[0]), DirectTransfer)
    assert isinstance(decode(messages[1]), Ack)
    assert isinstance(decode(messages[2]), Ping)
    assert isinstance(decode(messages[3]), Ack)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('send_ping_time', [3])
@pytest.mark.parametrize('max_unresponsive_time', [6])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_healthcheck_with_bad_peer(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    UnreliableTransport.droprate = 10  # Let's allow some messages to go through
    UnreliableTransport.network.counter = 1
    messages = setup_messages_cb()

    send_ping_time = app0.raiden.config['send_ping_time']
    max_unresponsive_time = app0.raiden.config['max_unresponsive_time']

    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]
    asset_manager1 = app1.raiden.managers_by_asset_address.values()[0]

    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert app1.raiden.address in asset_manager0.partneraddress_channel

    amount = 10
    app0.raiden.api.transfer(
        asset_manager0.asset_address,
        amount,
        target=app1.raiden.address,
    )

    gevent.sleep(2)
    assert asset_manager0.channelgraph.has_path(
        app0.raiden.address,
        app1.raiden.address
    )

    # At this point we should have sent a direct transfer and got back the ack
    assert len(messages) == 2  # DirectTransfer, Ack
    assert isinstance(decode(messages[0]), DirectTransfer)
    assert isinstance(decode(messages[1]), Ack)

    # now let's make things interesting and drop every message
    UnreliableTransport.droprate = 1
    UnreliableTransport.network.counter = 0
    gevent.sleep(send_ping_time)

    # At least 1 ping should have been sent by now but gotten no response
    assert len(messages) >= 3
    for msg in messages[2:]:
        assert isinstance(decode(msg), Ping)

    gevent.sleep(max_unresponsive_time - send_ping_time)
    # By now our peer has not replied and must have been removed from the graph
    assert not asset_manager0.channelgraph.has_path(
        app0.raiden.address,
        app1.raiden.address
    )
    final_messages_num = len(messages)
    # Let's make sure no new pings are sent afterwards
    gevent.sleep(2)
    assert len(messages) == final_messages_num


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_directtransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking
    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]

    other_key = PrivateKey(sha3("rainyweather"), ctx=GLOBAL_CTX, raw=True)
    other_address = privatekey_to_address(other_key.private_key)
    direct_transfer = DirectTransfer(
        identifier=1,
        nonce=1,
        asset=asset_manager0.asset_address,
        transferred_amount=10,
        recipient=app0.raiden.address,
        locksroot=sha3("muchrain")
    )
    sign_and_send(direct_transfer, other_key, other_address, app0)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_mediatedtransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking
    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]

    other_key = PrivateKey(sha3("rainstopped"), ctx=GLOBAL_CTX, raw=True)
    other_address = privatekey_to_address(other_key.private_key)
    amount = 10
    locksroot = sha3("muchsunny")
    mediated_transfer = MediatedTransfer(
        identifier=1,
        nonce=1,
        asset=asset_manager0.asset_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=locksroot,
        lock=Lock(amount, 1, locksroot),
        target=privatekey_to_address(sha3("cloudsagain")),
        initiator=other_address,
        fee=0
    )
    sign_and_send(mediated_transfer, other_key, other_address, app0)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_hashlocktransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking

    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]

    other_key = PrivateKey(sha3("rainstopped"), ctx=GLOBAL_CTX, raw=True)
    other_address = privatekey_to_address(other_key.private_key)
    amount = 10
    a_hash = sha3("foo")
    lock = Lock(amount, 1, a_hash)
    refund_transfer = RefundTransfer(
        identifier=1,
        nonce=1,
        asset=asset_manager0.asset_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=a_hash,
        lock=lock
    )
    sign_and_send(refund_transfer, other_key, other_address, app0)

    transfer_timeout = TransferTimeout(a_hash, a_hash)
    sign_and_send(transfer_timeout, other_key, other_address, app0)

    secret = Secret(1, a_hash, asset_manager0.asset_address)
    sign_and_send(secret, other_key, other_address, app0)

    secret_request = SecretRequest(1, a_hash, 1)
    sign_and_send(secret_request, other_key, other_address, app0)

    reveal_secret = RevealSecret(a_hash)
    sign_and_send(reveal_secret, other_key, other_address, app0)

    # Whenever processing of ConfirmTransfer is implemented test it here
    # too by removing the expectation of an exception
    with pytest.raises(KeyError):
        confirm_transfer = ConfirmTransfer(a_hash)
        sign_and_send(confirm_transfer, other_key, other_address, app0)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_outoforder(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

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

    # and now send one more direct transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    direct_transfer = DirectTransfer(
        identifier=asset_manager0.transfermanager.create_default_identifier(app1.raiden.address),
        nonce=1,
        asset=asset_manager0.asset_address,
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=HASH,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [2])
def test_receive_mediatedtransfer_outoforder(raiden_network, private_keys):
    alice_app = raiden_network[0]
    setup_messages_cb()

    asset_manager = alice_app.raiden.managers_by_asset_address.values()[0]
    asset_address = asset_manager.asset_address

    mt_helper = MediatedTransferTestHelper(raiden_network, asset_manager)
    initiator_address = alice_app.raiden.address
    path = mt_helper.get_paths_of_length(initiator_address, 2)

    alice_address, bob_address, charlie_address = path
    amount = 10
    alice_app.raiden.api.transfer(
        asset_address,
        amount,
        charlie_address,
    )
    gevent.sleep(1.)

    # and now send one more mediated transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    locksroot = HASH
    lock = Lock(amount, 1, locksroot)
    mediated_transfer = MediatedTransfer(
        identifier=asset_manager.transfermanager.create_default_identifier(charlie_address),
        nonce=1,
        asset=asset_address,
        transferred_amount=amount,
        recipient=bob_address,
        locksroot=locksroot,
        lock=lock,
        target=charlie_address,
        initiator=initiator_address,
        fee=0
    )
    alice_key = PrivateKey(private_keys[0])
    bob_app = mt_helper.get_app_from_address(bob_address)
    sign_and_send(mediated_transfer, alice_key, alice_address, bob_app)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [2])
def test_receive_mediatedtransfer_invalid_address(raiden_network, private_keys):
    alice_app = raiden_network[0]
    setup_messages_cb()

    asset_manager = alice_app.raiden.managers_by_asset_address.values()[0]
    asset_address = asset_manager.asset_address

    mt_helper = MediatedTransferTestHelper(raiden_network, asset_manager)
    initiator_address = alice_app.raiden.address
    path = mt_helper.get_paths_of_length(initiator_address, 2)

    alice_address, bob_address, charlie_address = path
    amount = 10
    alice_app.raiden.api.transfer(
        asset_address,
        amount,
        charlie_address,
    )
    gevent.sleep(1.)

    # and now send one more mediated transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    locksroot = HASH
    lock = Lock(amount, 1, locksroot)
    mediated_transfer = MediatedTransfer(
        identifier=asset_manager.transfermanager.create_default_identifier(charlie_address),
        nonce=1,
        asset=asset_address,
        transferred_amount=amount,
        recipient=bob_address,
        locksroot=locksroot,
        lock=lock,
        target=charlie_address,
        initiator=initiator_address,
        fee=0
    )
    alice_key = PrivateKey(private_keys[0])
    target_app = None
    for app in raiden_network:
        if app.raiden.address not in path:
            target_app = app
            break
    sign_and_send(mediated_transfer, alice_key, alice_address, target_app)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_wrongasset(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

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

    # and now send one more direct transfer with a mistaken asset address
    direct_transfer = DirectTransfer(
        identifier=asset_manager0.transfermanager.create_default_identifier(app1.raiden.address),
        nonce=2,
        asset=HASH[0:20],
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=HASH,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidlocksroot(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

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

    # and now send one more direct transfer with the locksoot not set correctly
    direct_transfer = DirectTransfer(
        identifier=asset_manager0.transfermanager.create_default_identifier(app1.raiden.address),
        nonce=2,
        asset=asset_manager0.asset_address,
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=HASH,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer, app0_key, app0.raiden.address, app1)
