# -*- coding: utf-8 -*-
from __future__ import print_function

import gevent
import pytest
from coincurve import PrivateKey

from raiden.messages import (
    Ack,
    decode,
    DirectTransfer,
    Lock,
    MediatedTransfer,
    Ping,
    RefundTransfer,
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.network.transport import UnreliableTransport
from raiden.tests.utils.messages import (
    setup_messages_cb,
    make_refund_transfer,
    MessageLogger,
)
from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    direct_transfer,
    transfer,
)
from raiden.tests.utils.network import CHAIN
from raiden.utils import pex, sha3, privatekey_to_address
from raiden.raiden_service import create_default_identifier
from raiden.tests.utils.blockchain import wait_until_block
from raiden.channel.netting_channel import (
    NODE_NETWORK_UNREACHABLE,
    NODE_NETWORK_UNKNOWN,
)

# pylint: disable=too-many-locals,too-many-statements,line-too-long
HASH = sha3('muchcodingsuchwow_______________')
HASH2 = sha3('terribleweathermuchstayinside___')


def unique(messages):
    seen = set()

    for m in messages:
        if m not in seen:
            seen.add(m)
            yield m


def get_messages_by_type(messages, type_):
    return [
        m
        for m in messages
        if isinstance(m, type_)
    ]


def assert_ack_for(receiver, message, message_list):
    direct_hash = sha3(message.encode() + receiver.raiden.address)

    assert any(
        ack.echo == direct_hash
        for ack in message_list
        if isinstance(ack, Ack)
    )


def sign_and_send(message, key, address, app):
    message.sign(key, address)
    message_data = str(message.packed().data)
    app.raiden.protocol.receive(message_data)
    # Give it some time to see if the unknown sender causes an error in the logic
    gevent.sleep(3)


class MediatedTransferTestHelper(object):
    def __init__(self, raiden_network, graph):
        self.raiden_network = raiden_network
        self.graph = graph
        self.token_address = graph.token_address
        self.ams_by_address = dict(
            (app.raiden.address, app.raiden.channelgraphs)
            for app in self.raiden_network
        )

    def get_channel(self, from_, to_):
        return self.ams_by_address[from_][self.token_address].partneraddress_channel[to_]

    def get_paths_of_length(self, initiator_address, num_hops):
        """
        Search for paths of length=num_of_hops starting from initiator_address
        """
        paths_length = self.graph.get_paths_of_length(
            initiator_address,
            num_hops,
        )

        assert paths_length, 'path must not be empty'

        for path in paths_length:
            assert len(path) == num_hops + 1
            assert path[0] == initiator_address

        return paths_length[0]

    def assert_path_in_shortest_paths(self, path, initiator_address, num_hops):
        _, _, charlie_address = path
        shortest_paths = list(self.graph.get_shortest_paths(
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


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_transfer(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    channel0 = graph0.partneraddress_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_channel

    amount = 10
    target = app1.raiden.address
    result = app0.raiden.transfer_async(
        graph0.token_address,
        amount,
        target,
    )

    result.wait(timeout=10)
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    decoded_messages = [decode(m) for m in messages]
    direct_messages = get_messages_by_type(decoded_messages, DirectTransfer)

    assert len(direct_messages) == 1
    assert direct_messages[0].transferred_amount == amount

    assert_ack_for(
        app1,
        direct_messages[0],
        decoded_messages,
    )


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('channels_per_node', [2])
@pytest.mark.parametrize('number_of_nodes', [10])
def test_mediated_transfer(raiden_network):
    alice_app = raiden_network[0]

    graph = alice_app.raiden.channelgraphs.values()[0]
    token_address = graph.token_address
    mt_helper = MediatedTransferTestHelper(raiden_network, graph)

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

    result = alice_app.raiden.transfer_async(
        token_address,
        amount,
        charlie_address,
    )

    assert channel_ab.locked == amount

    # Cannot assert the intermediary state of the channels since the code is
    # concurrently executed.
    # assert channel_ba.outstanding == amount
    # assert channel_bc.locked == amount
    # assert channel_cb.outstanding == amount

    assert result.wait(timeout=10)
    gevent.sleep(.1)  # wait for the other nodes to sync

    assert initial_balance_ab - amount == channel_ab.balance
    assert initial_balance_ba + amount == channel_ba.balance
    assert initial_balance_bc - amount == channel_bc.balance
    assert initial_balance_cb + amount == channel_cb.balance


@pytest.mark.xfail(reason='MediatedTransfer doesnt yet update balances on Refund')
@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('privatekey_seed', ['cancel_transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('token', [sha3('cancel_transfer')[:20]])
@pytest.mark.parametrize('deposit', [100])
def test_cancel_transfer(raiden_chain, token, deposit):

    app0, app1, app2, app3 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()
    mlogger = MessageLogger()

    assert_synched_channels(
        channel(app0, app1, token), deposit, [],
        channel(app1, app0, token), deposit, []
    )

    assert_synched_channels(
        channel(app1, app2, token), deposit, [],
        channel(app2, app1, token), deposit, []
    )

    assert_synched_channels(
        channel(app2, app3, token), deposit, [],
        channel(app3, app2, token), deposit, []
    )

    assert_synched_channels(
        channel(app0, app1, token), deposit, [],
        channel(app1, app0, token), deposit, []
    )

    # drain the channel app1 -> app2
    amount12 = 50
    direct_transfer(app1, app2, token, amount12)

    # drain the channel app2 -> app3
    amount23 = 80
    direct_transfer(app2, app3, token, amount23)

    assert_synched_channels(
        channel(app1, app2, token), deposit - amount12, [],
        channel(app2, app1, token), deposit + amount12, []
    )

    assert_synched_channels(
        channel(app2, app3, token), deposit - amount23, [],
        channel(app3, app2, token), deposit + amount23, []
    )

    # app1 -> app3 is the only available path but app2 -> app3 doesnt have
    # resources and needs to send a RefundTransfer down the path
    transfer(app0, app3, token, amount=50, identifier=1)

    assert_synched_channels(
        channel(app0, app1, token), deposit, [],
        channel(app1, app0, token), deposit, []
    )

    assert_synched_channels(
        channel(app1, app2, token), deposit - amount12, [],
        channel(app2, app1, token), deposit + amount12, []
    )

    assert_synched_channels(
        channel(app2, app3, token), deposit - amount23, [],
        channel(app3, app2, token), deposit + amount23, []
    )

    assert len(unique(messages)) == 12  # DT + DT + SMT + MT + RT + RT + ACKs

    app1_messages = mlogger.get_node_messages(pex(app1.raiden.address), only='sent')
    assert isinstance(app1_messages[-1], RefundTransfer)

    app2_messages = mlogger.get_node_messages(pex(app2.raiden.address), only='sent')
    assert isinstance(app2_messages[-1], RefundTransfer)


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_healthcheck_with_normal_peer(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    messages = setup_messages_cb()

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_channel

    amount = 10
    target = app1.raiden.address
    result = app0.raiden.transfer_async(
        graph0.token_address,
        amount,
        target,
    )
    assert result.wait(timeout=10)

    assert graph0.has_path(
        app0.raiden.address,
        app1.raiden.address
    )

    # At this point we should have sent a direct transfer and got back the ack
    # and gotten at least 1 ping - ack for a normal healthcheck
    decoded_messages = [decode(m) for m in unique(messages)]
    direct_messages = get_messages_by_type(decoded_messages, DirectTransfer)

    assert len(direct_messages) == 1
    assert_ack_for(app1, direct_messages[0], decoded_messages)

    ping_messages = get_messages_by_type(decoded_messages, Ping)
    assert ping_messages


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_healthcheck_with_bad_peer(raiden_network, nat_keepalive_retries, nat_keepalive_timeout):
    """ If the Ping messages are not answered, the node must be set to
    unreachable.
    """
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # Drop all Ping and Ack messages
    UnreliableTransport.droprate = 1
    UnreliableTransport.network.counter = 0

    app0.raiden.protocol.start_health_check(
        app1.raiden.address,
        ping_nonce=0,
    )

    graph0 = app0.raiden.channelgraphs.values()[0]
    partner_channel = graph0.partneraddress_channel[app1.raiden.address]

    assert partner_channel.network_state == NODE_NETWORK_UNKNOWN

    gevent.sleep(
        nat_keepalive_retries * nat_keepalive_timeout + 0.5
    )

    assert partner_channel.network_state == NODE_NETWORK_UNREACHABLE


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_directtransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking
    graph0 = app0.raiden.channelgraphs.values()[0]

    other_key = PrivateKey(HASH)
    other_address = privatekey_to_address(HASH)
    direct_transfer_message = DirectTransfer(
        identifier=1,
        nonce=1,
        token=graph0.token_address,
        transferred_amount=10,
        recipient=app0.raiden.address,
        locksroot=HASH
    )
    sign_and_send(direct_transfer_message, other_key, other_address, app0)


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_mediatedtransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking
    graph0 = app0.raiden.channelgraphs.values()[0]

    other_key = PrivateKey(HASH)
    other_address = privatekey_to_address(HASH)
    amount = 10
    locksroot = HASH
    mediated_transfer = MediatedTransfer(
        identifier=1,
        nonce=1,
        token=graph0.token_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=locksroot,
        lock=Lock(amount, 1, locksroot),
        target=privatekey_to_address(HASH2),
        initiator=other_address,
        fee=0
    )
    sign_and_send(mediated_transfer, other_key, other_address, app0)


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_hashlocktransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.channelgraphs.values()[0]

    other_key = PrivateKey(HASH2)
    other_address = privatekey_to_address(HASH2)
    amount = 10
    refund_transfer = make_refund_transfer(
        identifier=1,
        nonce=1,
        token=graph0.token_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=HASH,
        amount=amount,
        hashlock=HASH,
    )
    sign_and_send(refund_transfer, other_key, other_address, app0)

    secret = Secret(1, HASH, graph0.token_address)
    sign_and_send(secret, other_key, other_address, app0)

    secret_request = SecretRequest(1, HASH, 1)
    sign_and_send(secret_request, other_key, other_address, app0)

    reveal_secret = RevealSecret(HASH)
    sign_and_send(reveal_secret, other_key, other_address, app0)


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_outoforder(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    channel0 = graph0.partneraddress_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_channel

    amount = 10
    target = app1.raiden.address
    result = app0.raiden.transfer_async(
        graph0.token_address,
        amount,
        target,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    # and now send one more direct transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    identifier = create_default_identifier(
        app0.raiden.address,
        graph0.token_address,
        app1.raiden.address,
    )
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=1,
        token=graph0.token_address,
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=HASH,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer_message, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [2])
def test_receive_mediatedtransfer_outoforder(raiden_network, private_keys):
    alice_app = raiden_network[0]
    messages = setup_messages_cb()

    graph = alice_app.raiden.channelgraphs.values()[0]
    token_address = graph.token_address

    mt_helper = MediatedTransferTestHelper(raiden_network, graph)
    initiator_address = alice_app.raiden.address
    path = mt_helper.get_paths_of_length(initiator_address, 2)

    # make sure we have no messages before the transfer
    assert not messages

    alice_address, bob_address, charlie_address = path
    amount = 10
    result = alice_app.raiden.transfer_async(
        token_address,
        amount,
        charlie_address,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1.)

    # and now send one more mediated transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    locksroot = HASH
    lock = Lock(amount, 1, locksroot)
    identifier = create_default_identifier(
        alice_app.raiden.address,
        graph.token_address,
        charlie_address,
    )
    mediated_transfer = MediatedTransfer(
        identifier=identifier,
        nonce=1,
        token=token_address,
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


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [2])
def test_receive_mediatedtransfer_invalid_address(raiden_network, private_keys):
    alice_app = raiden_network[0]

    graph = alice_app.raiden.channelgraphs.values()[0]
    token_address = graph.token_address

    mt_helper = MediatedTransferTestHelper(raiden_network, graph)
    initiator_address = alice_app.raiden.address
    path = mt_helper.get_paths_of_length(initiator_address, 2)

    alice_address, bob_address, charlie_address = path
    amount = 10
    result = alice_app.raiden.transfer_async(
        token_address,
        amount,
        charlie_address,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1.)

    # and now send one more mediated transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    locksroot = HASH
    lock = Lock(amount, 1, locksroot)
    identifier = create_default_identifier(
        alice_app.raiden.address,
        graph.token_address,
        charlie_address,
    )
    mediated_transfer = MediatedTransfer(
        identifier=identifier,
        nonce=1,
        token=token_address,
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


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_wrongtoken(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    channel0 = graph0.partneraddress_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_channel

    amount = 10
    result = app0.raiden.transfer_async(
        graph0.token_address,
        amount,
        target=app1.raiden.address,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    # and now send one more direct transfer with a mistaken token address
    identifier = create_default_identifier(
        app0.raiden.address,
        graph0.token_address,
        app1.raiden.address,
    )
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=2,
        token=HASH[0:20],
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=HASH,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer_message, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidlocksroot(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    channel0 = graph0.partneraddress_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_channel

    amount = 10
    result = app0.raiden.transfer_async(
        graph0.token_address,
        amount,
        target=app1.raiden.address,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    # and now send one more direct transfer with the locksroot not set correctly
    identifier = create_default_identifier(
        app0.raiden.address,
        graph0.token_address,
        app1.raiden.address,
    )
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=2,
        token=graph0.token_address,
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=HASH,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer_message, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [30])
def test_transfer_from_outdated(raiden_network, settle_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    channel0 = graph0.partneraddress_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_channel

    amount = 10
    result = app0.raiden.transfer_async(
        graph0.token_address,
        amount,
        target=app1.raiden.address,
    )

    assert result.wait(timeout=10)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    channel1.external_state.netting_channel.close(
        channel1.received_transfers[-1],
    )

    wait_until_block(
        app1.raiden.chain,
        app1.raiden.chain.block_number() + 1
    )

    assert channel0.external_state.close_event.wait(timeout=25)
    assert channel1.external_state.close_event.wait(timeout=25)

    assert channel0.external_state.closed_block != 0
    assert channel1.external_state.closed_block != 0

    wait_until_block(
        app0.raiden.chain,
        app0.raiden.chain.block_number() + settle_timeout,
    )

    assert channel0.external_state.settle_event.wait(timeout=25)
    assert channel1.external_state.settle_event.wait(timeout=25)

    assert channel0.external_state.settled_block != 0
    assert channel1.external_state.settled_block != 0

    # and now receive one more transfer from the closed channel
    direct_transfer_message = DirectTransfer(
        identifier=1,
        nonce=1,
        token=graph0.token_address,
        transferred_amount=10,
        recipient=app0.raiden.address,
        locksroot=HASH
    )
    sign_and_send(
        direct_transfer_message,
        app1.raiden.private_key,
        app1.raiden.address, app1
    )
