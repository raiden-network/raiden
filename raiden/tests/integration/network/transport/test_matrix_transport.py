import json
import random
from unittest.mock import MagicMock

import gevent
import pytest
from eth_utils import to_checksum_address
from gevent import Timeout
from matrix_client.errors import MatrixRequestError

import raiden
from raiden.app import App
from raiden.constants import (
    DISCOVERY_DEFAULT_ROOM,
    EMPTY_SIGNATURE,
    MONITORING_BROADCASTING_ROOM,
    PATH_FINDING_BROADCASTING_ROOM,
    RoutingMode,
)
from raiden.exceptions import InsufficientEth
from raiden.messages.matrix import ToDevice
from raiden.messages.path_finding_service import PFSFeeUpdate
from raiden.messages.synchronization import Delivered, Processed
from raiden.network.transport.matrix import AddressReachability, MatrixTransport, _RetryQueue
from raiden.network.transport.matrix.client import Room
from raiden.network.transport.matrix.utils import UserPresence, make_room_alias, my_place_or_yours
from raiden.services import send_pfs_update, update_monitoring_service_from_balance_proof
from raiden.settings import MONITORING_REWARD
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.factories import HOP1
from raiden.tests.utils.mocks import MockRaidenService
from raiden.tests.utils.transfer import wait_assert
from raiden.transfer import views
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.transfer.state_change import ActionChannelClose, ActionUpdateTransportAuthData
from raiden.utils.typing import Address, List

HOP1_BALANCE_PROOF = factories.BalanceProofSignedStateProperties(pkey=factories.HOP1_KEY)
TIMEOUT_MESSAGE_RECEIVE = 15


class MessageHandler:
    def __init__(self, bag: set):
        self.bag = bag

    def on_message(self, _, message):
        self.bag.add(message)


def ping_pong_message_success(transport0, transport1):
    queueid0 = QueueIdentifier(
        recipient=transport0._raiden_service.address,
        canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
    )

    queueid1 = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
    )

    transport0_raiden_queues = views.get_all_messagequeues(
        views.state_from_raiden(transport0._raiden_service)
    )
    transport1_raiden_queues = views.get_all_messagequeues(
        views.state_from_raiden(transport1._raiden_service)
    )

    transport0_raiden_queues[queueid1] = []
    transport1_raiden_queues[queueid0] = []

    received_messages0 = transport0._raiden_service.message_handler.bag
    received_messages1 = transport1._raiden_service.message_handler.bag

    msg_id = random.randint(1e5, 9e5)

    ping_message = Processed(message_identifier=msg_id, signature=EMPTY_SIGNATURE)
    pong_message = Delivered(delivered_message_identifier=msg_id, signature=EMPTY_SIGNATURE)

    transport0_raiden_queues[queueid1].append(ping_message)

    transport0._raiden_service.sign(ping_message)
    transport1._raiden_service.sign(pong_message)
    transport0.send_async(queueid1, ping_message)

    with Timeout(TIMEOUT_MESSAGE_RECEIVE, exception=False):
        all_messages_received = False
        while not all_messages_received:
            all_messages_received = (
                ping_message in received_messages1 and pong_message in received_messages0
            )
            gevent.sleep(0.1)
    assert ping_message in received_messages1
    assert pong_message in received_messages0

    transport0_raiden_queues[queueid1].clear()
    transport1_raiden_queues[queueid0].append(ping_message)

    transport0._raiden_service.sign(pong_message)
    transport1._raiden_service.sign(ping_message)
    transport1.send_async(queueid0, ping_message)

    with Timeout(TIMEOUT_MESSAGE_RECEIVE, exception=False):
        all_messages_received = False
        while not all_messages_received:
            all_messages_received = (
                ping_message in received_messages0 and pong_message in received_messages1
            )
            gevent.sleep(0.1)
    assert ping_message in received_messages0
    assert pong_message in received_messages1

    transport1_raiden_queues[queueid0].clear()

    return all_messages_received


def is_reachable(transport: MatrixTransport, address: Address) -> bool:
    return (
        transport._address_mgr.get_address_reachability(address) is AddressReachability.REACHABLE
    )


def _wait_for_peer_reachability(
    transport: MatrixTransport,
    target_address: Address,
    target_reachability: AddressReachability,
    timeout: int = 5,
):
    with Timeout(timeout):
        while True:
            peer_reachability = transport._address_mgr.get_address_reachability(target_address)
            if peer_reachability is target_reachability:
                break
            gevent.sleep(0.1)


def wait_for_peer_unreachable(
    transport: MatrixTransport, target_address: Address, timeout: int = 5
):
    _wait_for_peer_reachability(
        transport=transport,
        target_address=target_address,
        target_reachability=AddressReachability.UNREACHABLE,
        timeout=timeout,
    )


def wait_for_peer_reachable(transport: MatrixTransport, target_address: Address, timeout: int = 5):
    _wait_for_peer_reachability(
        transport=transport,
        target_address=target_address,
        target_reachability=AddressReachability.REACHABLE,
        timeout=timeout,
    )


def wait_for_room_with_address(transport: MatrixTransport, address: Address, timeout: int = 10):
    with Timeout(timeout):
        while True:
            room = transport._get_room_for_address(address)
            if room is not None:
                break
            gevent.sleep(0.1)


@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [2])
def test_matrix_message_sync(matrix_transports):

    transport0, transport1 = matrix_transports

    transport0_messages = set()
    transport1_messages = set()

    transport0_message_handler = MessageHandler(transport0_messages)
    transport1_message_handler = MessageHandler(transport1_messages)

    raiden_service0 = MockRaidenService(transport0_message_handler)
    raiden_service1 = MockRaidenService(transport1_message_handler)

    raiden_service1.handle_and_track_state_changes = MagicMock()

    transport0.start(raiden_service0, [], None)
    transport1.start(raiden_service1, [], None)

    latest_auth_data = f"{transport1._user_id}/{transport1._client.api.token}"
    update_transport_auth_data = ActionUpdateTransportAuthData(latest_auth_data)
    with gevent.Timeout(2):
        wait_assert(
            raiden_service1.handle_and_track_state_changes.assert_called_with,
            [update_transport_auth_data],
        )

    transport0.start_health_check(transport1._raiden_service.address)
    transport1.start_health_check(transport0._raiden_service.address)

    queue_identifier = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        canonical_identifier=factories.UNIT_CANONICAL_ID,
    )

    raiden0_queues = views.get_all_messagequeues(views.state_from_raiden(raiden_service0))
    raiden0_queues[queue_identifier] = []

    for i in range(5):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        raiden0_queues[queue_identifier].append(message)
        transport0._raiden_service.sign(message)
        transport0.send_async(queue_identifier, message)

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while not len(transport0_messages) == 5:
            gevent.sleep(0.1)

        while not len(transport1_messages) == 5:
            gevent.sleep(0.1)

    # transport1 receives the `Processed` messages sent by transport0
    for i in range(5):
        assert any(m.message_identifier == i for m in transport1_messages)

    # transport0 answers with a `Delivered` for each `Processed`
    for i in range(5):
        assert any(m.delivered_message_identifier == i for m in transport0_messages)

    # Clear out queue
    raiden0_queues[queue_identifier] = []

    transport1.stop()

    wait_for_peer_unreachable(transport0, transport1._raiden_service.address)

    assert latest_auth_data

    # Send more messages while the other end is offline
    for i in range(10, 15):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        raiden0_queues[queue_identifier].append(message)
        transport0._raiden_service.sign(message)
        transport0.send_async(queue_identifier, message)

    # Should fetch the 5 messages sent while transport1 was offline
    transport1.start(transport1._raiden_service, [], latest_auth_data)
    transport1.start_health_check(transport0._raiden_service.address)

    with gevent.Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while len(transport1_messages) != 10:
            gevent.sleep(0.1)

        while len(transport0_messages) != 10:
            gevent.sleep(0.1)

    # transport1 receives the 5 new `Processed` messages sent by transport0
    for i in range(10, 15):
        assert any(m.message_identifier == i for m in transport1_messages)

    # transport0 answers with a `Delivered` for each one of the new `Processed`
    for i in range(10, 15):
        assert any(m.delivered_message_identifier == i for m in transport0_messages)


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_matrix_tx_error_handling(  # pylint: disable=unused-argument
    raiden_chain: List[App], token_addresses, request
):
    """Proxies exceptions must be forwarded by the transport."""
    if request.config.option.usepdb:
        pytest.skip("test fails with pdb")
    app0, app1 = raiden_chain
    token_address = token_addresses[0]

    channel_state = views.get_channelstate_for(
        chain_state=views.state_from_app(app0),
        token_network_registry_address=app0.raiden.default_registry.address,
        token_address=token_address,
        partner_address=app1.raiden.address,
    )
    burn_eth(app0.raiden.rpc_client)

    def make_tx(*args, **kwargs):  # pylint: disable=unused-argument
        close_channel = ActionChannelClose(canonical_identifier=channel_state.canonical_identifier)
        app0.raiden.handle_and_track_state_changes([close_channel])

    app0.raiden.transport._client.add_presence_listener(make_tx)

    exception = ValueError("Exception was not raised from the transport")
    with pytest.raises(InsufficientEth), gevent.Timeout(10, exception=exception):
        # Change presence in peer app to trigger callback in app0
        app1.raiden.transport._client.set_presence_state(UserPresence.UNAVAILABLE.value)
        app0.raiden.greenlet.get()


def test_matrix_message_retry(
    local_matrix_servers, retry_interval, retries_before_backoff, broadcast_rooms
):
    """ Test the retry mechanism implemented into the matrix client.
    The test creates a transport and sends a message. Given that the
    receiver was online, the initial message is sent but the receiver
    doesn't respond in time and goes offline. The retrier should then
    wait for the `retry_interval` duration to pass and send the message
    again but this won't work because the receiver is offline. Once
    the receiver comes back again, the message should be sent again.
    """
    partner_address = factories.make_address()

    transport = MatrixTransport(
        {
            "broadcast_rooms": broadcast_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
        }
    )
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(raiden_service, [], None)
    transport.log = MagicMock()

    # Receiver is online
    transport._address_mgr._address_to_reachability[
        partner_address
    ] = AddressReachability.REACHABLE

    queueid = QueueIdentifier(
        recipient=partner_address, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
    )
    chain_state = raiden_service.wal.state_manager.current_state

    retry_queue: _RetryQueue = transport._get_retrier(partner_address)
    assert bool(retry_queue), "retry_queue not running"

    # Send the initial message
    message = Processed(message_identifier=0, signature=EMPTY_SIGNATURE)
    transport._raiden_service.sign(message)
    chain_state.queueids_to_queues[queueid] = [message]
    retry_queue.enqueue_unordered(message)

    gevent.idle()
    assert transport._send_raw.call_count == 1

    # Receiver goes offline
    transport._address_mgr._address_to_reachability[
        partner_address
    ] = AddressReachability.UNREACHABLE

    with gevent.Timeout(retry_interval + 2):
        wait_assert(
            transport.log.debug.assert_called_with,
            "Partner not reachable. Skipping.",
            partner=to_checksum_address(partner_address),
            status=AddressReachability.UNREACHABLE,
        )

    # Retrier did not call send_raw given that the receiver is still offline
    assert transport._send_raw.call_count == 1

    # Receiver comes back online
    transport._address_mgr._address_to_reachability[
        partner_address
    ] = AddressReachability.REACHABLE

    # Retrier should send the message again
    with gevent.Timeout(retry_interval + 2):
        while transport._send_raw.call_count != 2:
            gevent.sleep(0.1)

    transport.stop()
    transport.greenlet.get()


def test_join_invalid_discovery(
    local_matrix_servers, retry_interval, retries_before_backoff, broadcast_rooms
):
    """join_broadcast_room tries to join on all servers on available_servers config

    If any of the servers isn't reachable by synapse, it'll return a 500 response, which needs
    to be handled, and if no discovery room is found on any of the available_servers, one in
    our current server should be created
    """
    transport = MatrixTransport(
        {
            "broadcast_rooms": broadcast_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": ["http://invalid.server"],
        }
    )
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(raiden_service, [], None)
    transport.log = MagicMock()
    discovery_room_name = make_room_alias(transport.chain_id, "discovery")
    assert isinstance(transport._broadcast_rooms.get(discovery_room_name), Room)

    transport.stop()
    transport.greenlet.get()


@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [3])
def test_matrix_cross_server_with_load_balance(matrix_transports):
    transport0, transport1, transport2 = matrix_transports
    received_messages0 = set()
    received_messages1 = set()
    received_messages2 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)
    message_handler2 = MessageHandler(received_messages2)

    raiden_service0 = MockRaidenService(message_handler0)
    raiden_service1 = MockRaidenService(message_handler1)
    raiden_service2 = MockRaidenService(message_handler2)

    transport0.start(raiden_service0, [], "")
    transport1.start(raiden_service1, [], "")
    transport2.start(raiden_service2, [], "")

    transport0.start_health_check(raiden_service1.address)
    transport0.start_health_check(raiden_service2.address)

    transport1.start_health_check(raiden_service0.address)
    transport1.start_health_check(raiden_service2.address)

    transport2.start_health_check(raiden_service0.address)
    transport2.start_health_check(raiden_service1.address)

    assert ping_pong_message_success(transport0, transport1)
    assert ping_pong_message_success(transport0, transport2)
    assert ping_pong_message_success(transport1, transport0)
    assert ping_pong_message_success(transport1, transport2)
    assert ping_pong_message_success(transport2, transport0)
    assert ping_pong_message_success(transport2, transport1)


def test_matrix_discovery_room_offline_server(
    local_matrix_servers, retries_before_backoff, retry_interval, broadcast_rooms
):

    transport = MatrixTransport(
        {
            "broadcast_rooms": broadcast_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0], "https://localhost:1"],
        }
    )
    transport.start(MockRaidenService(None), [], "")

    discovery_room_name = make_room_alias(transport.chain_id, "discovery")
    with gevent.Timeout(1):
        while not isinstance(transport._broadcast_rooms.get(discovery_room_name), Room):
            gevent.sleep(0.1)

    transport.stop()
    transport.greenlet.get()


@pytest.mark.parametrize(
    "broadcast_rooms", [[DISCOVERY_DEFAULT_ROOM, MONITORING_BROADCASTING_ROOM]]
)
def test_matrix_broadcast(
    local_matrix_servers, retries_before_backoff, retry_interval, broadcast_rooms
):
    transport = MatrixTransport(
        {
            "broadcast_rooms": broadcast_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
        }
    )
    transport.start(MockRaidenService(None), [], "")
    gevent.idle()

    ms_room_name = make_room_alias(transport.chain_id, MONITORING_BROADCASTING_ROOM)
    ms_room = transport._broadcast_rooms.get(ms_room_name)
    assert isinstance(ms_room, Room)

    ms_room.send_text = MagicMock(spec=ms_room.send_text)

    for i in range(5):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        transport._raiden_service.sign(message)
        transport.broadcast(MONITORING_BROADCASTING_ROOM, message)
    transport._schedule_new_greenlet(transport._broadcast_worker)

    gevent.idle()

    assert ms_room.send_text.call_count >= 1
    # messages could have been bundled
    call_args_str = " ".join(str(arg) for arg in ms_room.send_text.call_args_list)
    for i in range(5):
        assert f'"message_identifier": "{i}"' in call_args_str

    transport.stop()
    transport.greenlet.get()


@pytest.mark.parametrize(
    "broadcast_rooms", [[DISCOVERY_DEFAULT_ROOM, MONITORING_BROADCASTING_ROOM]]
)
def test_monitoring_broadcast_messages(
    local_matrix_servers, retry_interval, retries_before_backoff, monkeypatch, broadcast_rooms
):
    """
    Test that RaidenService broadcast RequestMonitoring messages to
    MONITORING_BROADCASTING_ROOM room on newly received balance proofs.
    """
    transport = MatrixTransport(
        {
            "broadcast_rooms": broadcast_rooms + [MONITORING_BROADCASTING_ROOM],
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
        }
    )
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)
    raiden_service.config = dict(services=dict(monitoring_enabled=True))

    transport.start(raiden_service, [], None)

    ms_room_name = make_room_alias(transport.chain_id, MONITORING_BROADCASTING_ROOM)
    ms_room = transport._broadcast_rooms.get(ms_room_name)
    assert isinstance(ms_room, Room)
    ms_room.send_text = MagicMock(spec=ms_room.send_text)

    raiden_service.transport = transport
    transport.log = MagicMock()

    balance_proof = factories.create(HOP1_BALANCE_PROOF)
    channel_state = factories.create(factories.NettingChannelStateProperties())
    channel_state.our_state.balance_proof = balance_proof
    channel_state.partner_state.balance_proof = balance_proof
    monkeypatch.setattr(
        raiden.transfer.views,
        "get_channelstate_by_canonical_identifier",
        lambda *a, **kw: channel_state,
    )
    monkeypatch.setattr(raiden.transfer.channel, "get_balance", lambda *a, **kw: 123)
    raiden_service.user_deposit.effective_balance.return_value = MONITORING_REWARD

    update_monitoring_service_from_balance_proof(
        raiden=raiden_service,
        chain_state=None,
        new_balance_proof=balance_proof,
        non_closing_participant=HOP1,
    )
    gevent.idle()

    with gevent.Timeout(2):
        while ms_room.send_text.call_count < 1:
            gevent.idle()
    assert ms_room.send_text.call_count == 1

    transport.stop()
    transport.greenlet.get()


@pytest.mark.parametrize("matrix_server_count", [1])
@pytest.mark.parametrize("route_mode", [RoutingMode.LOCAL, RoutingMode.PFS])
@pytest.mark.parametrize(
    "broadcast_rooms", [[DISCOVERY_DEFAULT_ROOM, PATH_FINDING_BROADCASTING_ROOM]]
)
def test_pfs_broadcast_messages(
    local_matrix_servers,
    retry_interval,
    retries_before_backoff,
    monkeypatch,
    broadcast_rooms,
    route_mode,
):
    """
    Test that RaidenService broadcasts PFSCapacityUpdate messages to
    PATH_FINDING_BROADCASTING_ROOM room on newly received balance proofs.
    """
    transport = MatrixTransport(
        {
            "broadcast_rooms": broadcast_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
        }
    )
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)
    raiden_service.config = dict(services=dict(monitoring_enabled=True))
    raiden_service.routing_mode = route_mode

    transport.start(raiden_service, [], None)

    pfs_room_name = make_room_alias(transport.chain_id, PATH_FINDING_BROADCASTING_ROOM)
    pfs_room = transport._broadcast_rooms.get(pfs_room_name)
    assert isinstance(pfs_room, Room)
    pfs_room.send_text = MagicMock(spec=pfs_room.send_text)

    raiden_service.transport = transport
    transport.log = MagicMock()

    # send PFSCapacityUpdate
    balance_proof = factories.create(HOP1_BALANCE_PROOF)
    channel_state = factories.create(factories.NettingChannelStateProperties())
    channel_state.our_state.balance_proof = balance_proof
    channel_state.partner_state.balance_proof = balance_proof
    monkeypatch.setattr(
        raiden.transfer.views,
        "get_channelstate_by_canonical_identifier",
        lambda *a, **kw: channel_state,
    )
    send_pfs_update(raiden=raiden_service, canonical_identifier=balance_proof.canonical_identifier)
    gevent.idle()
    with gevent.Timeout(2):
        while pfs_room.send_text.call_count < 1:
            gevent.idle()
    assert pfs_room.send_text.call_count == 1

    # send PFSFeeUpdate
    channel_state = factories.create(factories.NettingChannelStateProperties())
    fee_update = PFSFeeUpdate.from_channel_state(channel_state)
    fee_update.sign(raiden_service.signer)
    raiden_service.transport.broadcast(PATH_FINDING_BROADCASTING_ROOM, fee_update)
    with gevent.Timeout(2):
        while pfs_room.send_text.call_count < 2:
            gevent.idle()
    assert pfs_room.send_text.call_count == 2
    msg_data = json.loads(pfs_room.send_text.call_args[0][0])
    assert msg_data["type"] == "PFSFeeUpdate"

    transport.stop()
    transport.greenlet.get()


@pytest.mark.parametrize("number_of_transports", [2])
@pytest.mark.parametrize("matrix_server_count", [2])
def test_matrix_invite_private_room_happy_case(matrix_transports):
    """ Test that a room has been created between two communicating nodes."""
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)

    transport0, transport1 = matrix_transports

    transport0.start(raiden_service0, [], None)
    transport1.start(raiden_service1, [], None)

    transport0.start_health_check(transport1._raiden_service.address)
    transport1.start_health_check(transport0._raiden_service.address)

    room = transport0._get_room_for_address(raiden_service1.address)
    # Transport0 is on the higher end of the lexical order of the addresses.
    # It did not create the room and therefore we check that the other
    # node creates it.
    if room is None:
        room = transport1._maybe_create_room_for_address(raiden_service0.address)
    room_id = room.room_id

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while True:
            try:
                room_state0 = transport0._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    assert room_state0 is not None

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while True:
            try:
                room_state1 = transport1._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    assert room_state1 is not None


@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [2])
def test_matrix_invite_retry_with_offline_invitee(matrix_transports):
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)

    transport0, transport1 = matrix_transports

    room_creator_address = my_place_or_yours(raiden_service0.address, raiden_service1.address)
    if room_creator_address == raiden_service0.address:
        inviter_service = raiden_service0
        invitee_service = raiden_service1

        inviter_transport = transport0
        invitee_transport = transport1
    else:
        inviter_service = raiden_service1
        invitee_service = raiden_service0

        inviter_transport = transport1
        invitee_transport = transport0

    inviter_transport.start(inviter_service, [], None)
    invitee_transport.start(invitee_service, [], None)

    inviter_transport.start_health_check(invitee_service.address)
    invitee_transport.start_health_check(inviter_service.address)

    assert is_reachable(inviter_transport, invitee_service.address)
    assert is_reachable(invitee_transport, inviter_service.address)

    invitee_transport.stop()
    wait_for_peer_unreachable(inviter_transport, invitee_service.address)
    assert not is_reachable(inviter_transport, invitee_service.address)

    room_id = inviter_transport._get_room_for_address(invitee_service.address).room_id

    invitee_transport.start(invitee_service, [], None)
    invitee_transport.start_health_check(inviter_service.address)

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while True:
            try:
                room_state0 = inviter_transport._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    assert room_state0 is not None

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while True:
            try:
                room_state1 = invitee_transport._client.api.get_room_state(room_id)
                break
            except MatrixRequestError as ex:
                print(ex, transport0._client.user_id, transport1._client.user_id)
                gevent.sleep(0.5)

    assert room_state1 is not None


@pytest.mark.parametrize("number_of_transports", [2])
@pytest.mark.parametrize("matrix_server_count", [2])
def test_matrix_invitee_receives_invite_on_restart(matrix_transports):
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)

    transport0, transport1 = matrix_transports

    room_creator_address = my_place_or_yours(raiden_service0.address, raiden_service1.address)
    if room_creator_address == raiden_service0.address:
        inviter_service = raiden_service0
        invitee_service = raiden_service1

        inviter_transport = transport0
        invitee_transport = transport1
    else:
        inviter_service = raiden_service1
        invitee_service = raiden_service0

        inviter_transport = transport1
        invitee_transport = transport0

    inviter_transport.start(inviter_service, [], None)
    invitee_transport.start(invitee_service, [], None)

    inviter_transport.start_health_check(invitee_service.address)
    invitee_transport.start_health_check(inviter_service.address)

    wait_for_peer_reachable(inviter_transport, invitee_service.address)
    wait_for_peer_reachable(invitee_transport, inviter_service.address)

    assert is_reachable(invitee_transport, inviter_service.address)
    assert is_reachable(inviter_transport, invitee_service.address)

    invitee_transport.stop()

    wait_for_peer_unreachable(inviter_transport, invitee_service.address)
    assert not is_reachable(inviter_transport, invitee_service.address)

    room_id = inviter_transport._get_room_for_address(invitee_service.address).room_id
    invitee_transport.start(invitee_service, [], None)
    invitee_transport.start_health_check(inviter_service.address)

    inviter_transport.stop()

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while True:
            try:
                room_state1 = invitee_transport._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    assert room_state1 is not None


@pytest.mark.parametrize("matrix_server_count", [3])
@pytest.mark.parametrize("number_of_transports", [3])
def test_matrix_user_roaming(matrix_transports):
    transport0, transport1, transport2 = matrix_transports
    received_messages0 = set()
    received_messages1 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)

    raiden_service0 = MockRaidenService(message_handler0)
    raiden_service1 = MockRaidenService(message_handler1)

    transport0.start(raiden_service0, [], "")
    transport1.start(raiden_service1, [], "")

    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)

    transport0.stop()

    wait_for_peer_unreachable(transport1, raiden_service0.address)
    assert not is_reachable(transport1, raiden_service0.address)

    transport2.start(raiden_service0, [], "")
    transport2.start_health_check(raiden_service1.address)

    assert ping_pong_message_success(transport2, transport1)

    transport2.stop()

    wait_for_peer_unreachable(transport1, raiden_service0.address)
    assert not is_reachable(transport1, raiden_service0.address)

    transport0.start(raiden_service0, [], "")
    transport0.start_health_check(raiden_service1.address)

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while not is_reachable(transport1, raiden_service0.address):
            gevent.sleep(0.1)

    assert is_reachable(transport1, raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)


@pytest.mark.parametrize("matrix_server_count", [3])
@pytest.mark.parametrize("number_of_transports", [6])
def test_matrix_multi_user_roaming(matrix_transports):
    # 6 transports on 3 servers, where (0,3), (1,4), (2,5) are one the same server
    (
        transport_rs0_0,
        transport_rs0_1,
        transport_rs0_2,
        transport_rs1_0,
        transport_rs1_1,
        transport_rs1_2,
    ) = matrix_transports
    received_messages0 = set()
    received_messages1 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)

    raiden_service0 = MockRaidenService(message_handler0)
    raiden_service1 = MockRaidenService(message_handler1)

    # Both nodes on the same server
    transport_rs0_0.start(raiden_service0, [], "")
    transport_rs1_0.start(raiden_service1, [], "")

    transport_rs0_0.start_health_check(raiden_service1.address)
    transport_rs1_0.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_0, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_0, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_0, transport_rs1_0)

    # Node two switches to second server
    transport_rs1_0.stop()
    wait_for_peer_unreachable(transport_rs0_0, raiden_service1.address)

    transport_rs1_1.start(raiden_service1, [], "")
    transport_rs1_1.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_0, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_1, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_0, transport_rs1_1)

    # Node two switches to third server
    transport_rs1_1.stop()
    wait_for_peer_unreachable(transport_rs0_0, raiden_service1.address)

    transport_rs1_2.start(raiden_service1, [], "")
    transport_rs1_2.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_0, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_2, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_0, transport_rs1_2)
    # Node one switches to second server, Node two back to first
    transport_rs0_0.stop()
    transport_rs1_2.stop()

    transport_rs0_1.start(raiden_service0, [], "")
    transport_rs1_0.start(raiden_service1, [], "")

    transport_rs0_1.start_health_check(raiden_service1.address)
    transport_rs1_0.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_1, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_0, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_1, transport_rs1_0)

    # Node two joins on second server again
    transport_rs1_0.stop()
    wait_for_peer_unreachable(transport_rs0_1, raiden_service1.address)

    transport_rs1_1.start(raiden_service1, [], "")
    transport_rs1_1.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_1, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_1, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_1, transport_rs1_1)

    # Node two switches to third server
    transport_rs1_1.stop()
    wait_for_peer_unreachable(transport_rs0_1, raiden_service1.address)

    transport_rs1_2.start(raiden_service1, [], "")
    transport_rs1_2.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_1, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_2, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_1, transport_rs1_2)

    # Node one switches to third server, node two switches to first server
    transport_rs0_1.stop()
    transport_rs1_2.stop()

    transport_rs0_2.start(raiden_service0, [], "")
    transport_rs0_2.start_health_check(raiden_service1.address)
    transport_rs1_0.start(raiden_service1, [], "")
    transport_rs1_0.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_2, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_0, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_2, transport_rs1_0)

    # Node two switches to second server
    transport_rs1_0.stop()
    wait_for_peer_unreachable(transport_rs0_2, raiden_service1.address)

    transport_rs1_1.start(raiden_service1, [], "")
    transport_rs1_1.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_2, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_1, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_2, transport_rs1_1)

    # Node two joins on third server
    transport_rs1_1.stop()
    wait_for_peer_unreachable(transport_rs0_2, raiden_service1.address)

    transport_rs1_2.start(raiden_service1, [], "")
    transport_rs1_2.start_health_check(raiden_service0.address)

    wait_for_room_with_address(transport_rs0_2, raiden_service1.address)
    wait_for_room_with_address(transport_rs1_2, raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_2, transport_rs1_2)


@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [2])
def test_reproduce_handle_invite_send_race_issue_3588(matrix_transports):
    transport0, transport1 = matrix_transports
    received_messages0 = set()
    received_messages1 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)

    raiden_service0 = MockRaidenService(message_handler0)
    raiden_service1 = MockRaidenService(message_handler1)

    transport0.start(raiden_service0, [], "")
    transport1.start(raiden_service1, [], "")
    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)


@pytest.mark.parametrize("matrix_server_count", [1])
@pytest.mark.parametrize("number_of_transports", [2])
def test_send_to_device(matrix_transports):
    transport0, transport1 = matrix_transports
    received_messages0 = set()
    received_messages1 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)

    raiden_service0 = MockRaidenService(message_handler0)
    raiden_service1 = MockRaidenService(message_handler1)
    transport1._receive_to_device = MagicMock()

    transport0.start(raiden_service0, [], "")
    transport1.start(raiden_service1, [], "")

    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)

    message = Processed(message_identifier=1, signature=EMPTY_SIGNATURE)
    transport0._raiden_service.sign(message)
    transport0.send_to_device(raiden_service1.address, message)

    transport1._receive_to_device.assert_not_called()
    message = ToDevice(message_identifier=1, signature=EMPTY_SIGNATURE)
    transport0._raiden_service.sign(message)
    transport0.send_to_device(raiden_service1.address, message)
    with gevent.Timeout(2):
        wait_assert(transport1._receive_to_device.assert_called)
