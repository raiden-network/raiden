# -*- coding: utf-8 -*-
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
from raiden.tests.utils.transport import UnreliableTransport
from raiden.tests.utils.messages import (
    setup_messages_cb,
    make_refund_transfer,
)
from raiden.tests.utils.transport import (
    MessageLoggerTransport,
)
from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    direct_transfer,
    transfer,
)
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.factories import (
    UNIT_SECRET,
    UNIT_HASHLOCK,
    make_address,
    make_privkey_address,
)
from raiden.utils import (
    sha3,
    privatekey_to_address,
)
from raiden.raiden_service import create_default_identifier
from raiden.tests.utils.blockchain import wait_until_block
from raiden.network.protocol import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
    NODE_NETWORK_UNREACHABLE,
)


# pylint: disable=too-many-locals,too-many-statements,line-too-long
HASH2 = sha3(b'terribleweathermuchstayinside___')


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
    message_data = bytes(message.packed().data)
    app.raiden.protocol.receive(message_data)
    # Give it some time to see if the unknown sender causes an error in the logic
    gevent.sleep(3)


class MediatedTransferTestHelper:
    def __init__(self, raiden_network, graph):
        self.raiden_network = raiden_network
        self.graph = graph
        self.token_address = graph.token_address
        self.nodes = {
            app.raiden.address: app
            for app in self.raiden_network
        }

    def get_channel(self, from_, to_):
        raiden = self.nodes[from_].raiden
        graph = raiden.token_to_channelgraph[self.token_address]
        return graph.partneraddress_to_channel[to_]

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


@pytest.mark.parametrize('number_of_nodes', [2])
def test_direct_transfer(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    messages = setup_messages_cb()

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    channel0 = graph0.partneraddress_to_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_to_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    amount = 10
    target = app1.raiden.address
    result = app0.raiden.direct_transfer_async(
        graph0.token_address,
        amount,
        target,
        identifier=1,
    )

    assert result.wait(timeout=10)
    gevent.sleep(5)

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


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_transfer_channels(raiden_network, token_addresses):
    """ When the node has no channels it should fail without raising exceptions. """
    token_address = token_addresses[0]
    app0, app1 = raiden_network

    amount = 10
    async_result = app0.raiden.mediated_transfer_async(
        token_address,
        amount,
        app1.raiden.address,
        identifier=1,
    )

    assert async_result.wait() is False


@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('channels_per_node', [1])
def test_transfer_noroutes(raiden_network, token_addresses):
    """ When there are no routes it should fail without raising exceptions. """
    # Topology:
    #   App0 <-> App1 App2 <-> App3
    #
    app0, _, app2, app3 = raiden_network

    token_address = token_addresses[0]

    amount = 10
    async_result = app0.raiden.mediated_transfer_async(
        token_address,
        amount,
        app2.raiden.address,
        identifier=1,
    )
    assert async_result.wait() is False

    async_result = app0.raiden.mediated_transfer_async(
        token_address,
        amount,
        app3.raiden.address,
        identifier=1,
    )
    assert async_result.wait() is False


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [4])
def test_mediated_transfer(raiden_network):
    alice_app = raiden_network[0]

    graph = list(alice_app.raiden.token_to_channelgraph.values())[0]
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

    result = alice_app.raiden.mediated_transfer_async(
        token_address,
        amount,
        charlie_address,
        identifier=1,
    )

    # The assert is for an in-flight transfer
    assert not result.ready()
    assert channel_ab.locked == amount

    # Cannot assert the intermediary state of the channels since the code is
    # concurrently executed.
    # assert channel_ba.outstanding == amount
    # assert channel_bc.locked == amount
    # assert channel_cb.outstanding == amount

    assert result.wait(timeout=1)
    gevent.sleep(.1)  # wait for the other nodes to sync

    assert initial_balance_ab - amount == channel_ab.balance
    assert initial_balance_ba + amount == channel_ba.balance
    assert initial_balance_bc - amount == channel_bc.balance
    assert initial_balance_cb + amount == channel_cb.balance


@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_direct_transfer_exceeding_distributable(raiden_network, token_addresses, deposit):
    alice_app, bob_app = raiden_network
    token_address = token_addresses[0]

    result = alice_app.raiden.direct_transfer_async(
        token_address,
        deposit * 2,
        bob_app.raiden.address,
        identifier=1,
    )

    assert not result.wait(timeout=10)


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer_with_entire_deposit(raiden_network, token_addresses, deposit):
    alice_app, bob_app, charlie_app = raiden_network
    token_address = token_addresses[0]

    result = alice_app.raiden.mediated_transfer_async(
        token_address,
        deposit,
        charlie_app.raiden.address,
        identifier=1,
    )

    channel_ab = channel(alice_app, bob_app, token_address)
    assert channel_ab.locked == deposit
    assert channel_ab.outstanding == 0
    assert channel_ab.distributable == 0

    assert result.wait(timeout=10)
    gevent.sleep(.1)  # wait for charlie to sync

    result = charlie_app.raiden.mediated_transfer_async(
        token_address,
        deposit * 2,
        alice_app.raiden.address,
        identifier=1,
    )
    assert result.wait(timeout=10)


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('transport_class', [MessageLoggerTransport])
def test_cancel_transfer(raiden_chain, token_addresses, deposit):
    """ A failed transfer must send a refund back.

    TODO:
        - Unlock the token on refund #1091
        - Clear the merkletree and update the locked amount #193
        - Remove the refund message type #490
    """
    # Topology:
    #
    #  0 -> 1 -> 2
    #
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    token = token_addresses[0]

    assert_synched_channels(
        channel(app0, app1, token), deposit, [],
        channel(app1, app0, token), deposit, []
    )

    assert_synched_channels(
        channel(app1, app2, token), deposit, [],
        channel(app2, app1, token), deposit, []
    )

    # make a transfer to test the path app0 -> app1 -> app2
    identifier_path = 1
    amount_path = 1
    transfer(app0, app2, token, amount_path, identifier_path)

    # drain the channel app1 -> app2
    identifier_drain = 2
    amount_drain = int(deposit * 0.8)
    direct_transfer(app1, app2, token, amount_drain, identifier_drain)

    # wait for the nodes to sync
    gevent.sleep(0.2)

    assert_synched_channels(
        channel(app0, app1, token), deposit - amount_path, [],
        channel(app1, app0, token), deposit + amount_path, []
    )

    assert_synched_channels(
        channel(app1, app2, token), deposit - amount_path - amount_drain, [],
        channel(app2, app1, token), deposit + amount_path + amount_drain, []
    )

    # app0 -> app1 -> app2 is the only available path but the channel app1 ->
    # app2 doesnt have resources and needs to send a RefundTransfer down the
    # path
    identifier_refund = 3
    amount_refund = 50
    async_result = app0.raiden.mediated_transfer_async(
        token,
        amount_refund,
        app2.raiden.address,
        identifier_refund,
    )
    assert async_result.wait() is False, 'there is no path with capacity, the transfer must fail'

    gevent.sleep(0.2)

    # A lock structure with the correct amount
    app0_messages = app0.raiden.protocol.transport.get_sent_messages(app0.raiden.address)
    mediated_message = list(
        message
        for message in app0_messages
        if isinstance(message, MediatedTransfer) and message.target == app2.raiden.address
    )[-1]
    assert mediated_message

    app1_messages = app1.raiden.protocol.transport.get_sent_messages(app1.raiden.address)
    refund_message = next(
        message
        for message in app1_messages
        if isinstance(message, RefundTransfer) and message.recipient == app0.raiden.address
    )
    assert refund_message

    assert mediated_message.lock.amount == refund_message.lock.amount
    assert mediated_message.lock.hashlock == refund_message.lock.hashlock
    assert mediated_message.lock.expiration > refund_message.lock.expiration

    # Both channels have the amount locked because of the refund message
    assert_synched_channels(
        channel(app0, app1, token), deposit - amount_path, [refund_message.lock],
        channel(app1, app0, token), deposit + amount_path, [mediated_message.lock],
    )

    assert_synched_channels(
        channel(app1, app2, token), deposit - amount_path - amount_drain, [],
        channel(app2, app1, token), deposit + amount_path + amount_drain, []
    )


@pytest.mark.parametrize('number_of_nodes', [2])
def test_healthcheck_with_normal_peer(raiden_network, token_addresses):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    messages = setup_messages_cb()

    token_address = token_addresses[0]

    address0 = app0.raiden.address
    address1 = app1.raiden.address

    graph0 = app0.raiden.token_to_channelgraph[token_address]
    graph1 = app1.raiden.token_to_channelgraph[token_address]

    # check the nodes have a channel
    assert graph0.token_address == graph1.token_address
    assert address1 in graph0.partneraddress_to_channel
    assert address0 in graph1.partneraddress_to_channel

    # check both have started the healthcheck
    assert address0 in app1.raiden.protocol.addresses_events
    assert address1 in app0.raiden.protocol.addresses_events

    # wait for the healthcheck task to send a ping
    gevent.sleep(app0.raiden.protocol.nat_keepalive_timeout)
    gevent.sleep(app1.raiden.protocol.nat_keepalive_timeout)

    decoded_messages = [decode(m) for m in set(messages)]
    ping_messages = get_messages_by_type(decoded_messages, Ping)

    assert ping_messages


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_healthcheck_with_unconnected_node(raiden_network, nat_keepalive_timeout):
    """ Nodes start at the unknown state. """
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    address0 = app0.raiden.address
    address1 = app1.raiden.address

    assert app0.raiden.protocol.nodeaddresses_networkstatuses[address1] == NODE_NETWORK_UNKNOWN
    assert app1.raiden.protocol.nodeaddresses_networkstatuses[address0] == NODE_NETWORK_UNKNOWN

    app0.raiden.start_health_check_for(address1)

    gevent.sleep(nat_keepalive_timeout)

    assert app0.raiden.protocol.nodeaddresses_networkstatuses[address1] == NODE_NETWORK_REACHABLE
    assert app1.raiden.protocol.nodeaddresses_networkstatuses[address0] == NODE_NETWORK_UNKNOWN


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('transport_class', [UnreliableTransport])
def test_healthcheck_with_bad_peer(raiden_network, nat_keepalive_retries, nat_keepalive_timeout):
    """ If the Ping messages are not answered, the node must be set to
    unreachable.
    """
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    address0 = app0.raiden.address
    address1 = app1.raiden.address

    assert app0.raiden.protocol.nodeaddresses_networkstatuses[address1] == NODE_NETWORK_REACHABLE
    assert app1.raiden.protocol.nodeaddresses_networkstatuses[address0] == NODE_NETWORK_REACHABLE

    # Drop all Ping and Ack messages
    app0.raiden.protocol.transport.droprate = 1
    app1.raiden.protocol.transport.droprate = 1

    gevent.sleep(
        (nat_keepalive_retries + 2) * nat_keepalive_timeout
    )

    assert app0.raiden.protocol.nodeaddresses_networkstatuses[address1] == NODE_NETWORK_UNREACHABLE
    assert app1.raiden.protocol.nodeaddresses_networkstatuses[address0] == NODE_NETWORK_UNREACHABLE


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_directtransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking
    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]

    other_key, other_address = make_privkey_address()
    direct_transfer_message = DirectTransfer(
        identifier=1,
        nonce=1,
        token=graph0.token_address,
        channel=other_address,
        transferred_amount=10,
        recipient=app0.raiden.address,
        locksroot=UNIT_HASHLOCK,
    )
    sign_and_send(direct_transfer_message, other_key, other_address, app0)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_mediatedtransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking
    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]

    other_key, other_address = make_privkey_address()
    amount = 10
    mediated_transfer = MediatedTransfer(
        identifier=1,
        nonce=1,
        token=graph0.token_address,
        channel=other_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=UNIT_HASHLOCK,
        lock=Lock(amount, 1, UNIT_HASHLOCK),
        target=make_address(),
        initiator=other_address,
        fee=0
    )
    sign_and_send(mediated_transfer, other_key, other_address, app0)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_hashlocktransfer_unknown(raiden_network):
    app0 = raiden_network[0]  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]

    other_key = PrivateKey(HASH2)
    other_address = privatekey_to_address(HASH2)
    amount = 10
    refund_transfer = make_refund_transfer(
        identifier=1,
        nonce=1,
        token=graph0.token_address,
        channel=other_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=UNIT_HASHLOCK,
        amount=amount,
        hashlock=UNIT_HASHLOCK,
    )
    sign_and_send(refund_transfer, other_key, other_address, app0)

    secret = Secret(
        identifier=1,
        nonce=1,
        channel=make_address(),
        transferred_amount=amount,
        locksroot=UNIT_HASHLOCK,
        secret=UNIT_SECRET,
    )
    sign_and_send(secret, other_key, other_address, app0)

    secret_request = SecretRequest(1, UNIT_HASHLOCK, 1)
    sign_and_send(secret_request, other_key, other_address, app0)

    reveal_secret = RevealSecret(UNIT_SECRET)
    sign_and_send(reveal_secret, other_key, other_address, app0)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_outoforder(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    channel0 = graph0.partneraddress_to_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_to_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    amount = 10
    target = app1.raiden.address
    result = app0.raiden.direct_transfer_async(
        graph0.token_address,
        amount,
        target,
        identifier=1,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    # and now send one more direct transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    identifier = create_default_identifier()
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=1,
        token=graph0.token_address,
        channel=channel0.channel_address,
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=UNIT_HASHLOCK,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer_message, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_receive_mediatedtransfer_outoforder(raiden_network, private_keys):
    alice_app = raiden_network[0]
    bob_app = raiden_network[1]
    charlie_app = raiden_network[2]

    graph = list(alice_app.raiden.token_to_channelgraph.values())[0]
    token_address = graph.token_address

    channel0 = channel(
        alice_app,
        bob_app,
        token_address,
    )

    amount = 10
    result = alice_app.raiden.mediated_transfer_async(
        token_address,
        amount,
        charlie_app.raiden.address,
        identifier=1,
    )

    assert result.wait(timeout=10)

    lock = Lock(amount, 1, UNIT_HASHLOCK)
    identifier = create_default_identifier()
    mediated_transfer = MediatedTransfer(
        identifier=identifier,
        nonce=1,
        token=token_address,
        channel=channel0.channel_address,
        transferred_amount=amount,
        recipient=bob_app.raiden.address,
        locksroot=UNIT_HASHLOCK,
        lock=lock,
        target=charlie_app.raiden.address,
        initiator=alice_app.raiden.address,
        fee=0
    )
    alice_key = PrivateKey(private_keys[0])

    # send the invalid mediated transfer from alice to bob with the same nonce
    sign_and_send(
        mediated_transfer,
        alice_key,
        alice_app.raiden.address,
        bob_app,
    )


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_receive_mediatedtransfer_invalid_address(raiden_chain, token_addresses):
    app0, app1, app2 = raiden_chain
    token_address = token_addresses[0]

    amount = 10
    result = app0.raiden.mediated_transfer_async(
        token_address,
        amount,
        app2.raiden.address,
        identifier=1,
    )
    assert result.wait(timeout=10)

    # and now send one more mediated transfer with the same nonce, simulating
    # an out-of-order/resent message that arrives late
    channel0 = channel(app0, app1, token_address)
    lock = Lock(amount, 1, UNIT_HASHLOCK)
    identifier = create_default_identifier()
    mediated_transfer = MediatedTransfer(
        identifier=identifier,
        nonce=1,
        token=token_address,
        channel=channel0.channel_address,
        transferred_amount=amount,
        recipient=app1.raiden.address,
        locksroot=UNIT_HASHLOCK,
        lock=lock,
        target=app2.raiden.address,
        initiator=app0.raiden.address,
        fee=0
    )

    sign_and_send(
        mediated_transfer,
        app0.raiden.private_key,
        app0.raiden.address,
        app1,
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_wrongtoken(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    channel0 = graph0.partneraddress_to_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_to_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    amount = 10
    result = app0.raiden.direct_transfer_async(
        graph0.token_address,
        amount,
        target=app1.raiden.address,
        identifier=1,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    # and now send one more direct transfer with a mistaken token address
    identifier = create_default_identifier()
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=2,
        token=make_address(),
        channel=channel0.channel_address,
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=UNIT_HASHLOCK,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer_message, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_receive_directtransfer_invalidlocksroot(raiden_network, private_keys):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    channel0 = graph0.partneraddress_to_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_to_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    amount = 10
    result = app0.raiden.direct_transfer_async(
        graph0.token_address,
        amount,
        target=app1.raiden.address,
        identifier=1,
    )

    assert result.wait(timeout=10)
    gevent.sleep(1)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    # and now send one more direct transfer with the locksroot not set correctly
    identifier = create_default_identifier()
    direct_transfer_message = DirectTransfer(
        identifier=identifier,
        nonce=2,
        token=graph0.token_address,
        channel=channel0.channel_address,
        transferred_amount=10,
        recipient=app1.raiden.address,
        locksroot=UNIT_HASHLOCK,
    )
    app0_key = PrivateKey(private_keys[0])
    sign_and_send(direct_transfer_message, app0_key, app0.raiden.address, app1)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [30])
def test_transfer_from_outdated(raiden_network, settle_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    channel0 = graph0.partneraddress_to_channel[app1.raiden.address]
    channel1 = graph1.partneraddress_to_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    assert graph0.token_address == graph1.token_address
    assert app1.raiden.address in graph0.partneraddress_to_channel

    amount = 10
    result = app0.raiden.direct_transfer_async(
        graph0.token_address,
        amount,
        target=app1.raiden.address,
        identifier=1,
    )

    assert result.wait(timeout=10)

    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, []
    )

    channel1.external_state.close(channel1.our_state.balance_proof)

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
        channel=channel0.channel_address,
        transferred_amount=10,
        recipient=app0.raiden.address,
        locksroot=UNIT_HASHLOCK,
    )

    sign_and_send(
        direct_transfer_message,
        app1.raiden.private_key,
        app1.raiden.address,
        app1,
    )
