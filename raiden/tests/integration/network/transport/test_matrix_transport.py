import json
import random
from unittest.mock import MagicMock

import gevent
import pytest
from eth_utils import to_checksum_address
from gevent import Timeout
from matrix_client.errors import MatrixRequestError

import raiden
from raiden.constants import (
    EMPTY_SIGNATURE,
    MONITORING_BROADCASTING_ROOM,
    PATH_FINDING_BROADCASTING_ROOM,
    UINT64_MAX,
    RoutingMode,
)
from raiden.exceptions import InsufficientFunds
from raiden.messages.matrix import ToDevice
from raiden.messages.path_finding_service import PFSFeeUpdate
from raiden.messages.synchronization import Delivered, Processed
from raiden.messages.transfers import SecretRequest
from raiden.network.transport.matrix import AddressReachability, MatrixTransport, _RetryQueue
from raiden.network.transport.matrix.client import Room
from raiden.network.transport.matrix.utils import make_room_alias
from raiden.services import send_pfs_update, update_monitoring_service_from_balance_proof
from raiden.storage.serialization import JSONSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.mocks import MockRaidenService
from raiden.transfer import views
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_GLOBAL_QUEUE, QueueIdentifier
from raiden.transfer.state_change import ActionChannelClose, ActionUpdateTransportAuthData
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import Address, List, Optional, Union

USERID0 = "@Arthur:RestaurantAtTheEndOfTheUniverse"
USERID1 = "@Alice:Wonderland"
HOP1_BALANCE_PROOF = factories.BalanceProofSignedStateProperties(pkey=factories.HOP1_KEY)


class MessageHandler:
    def __init__(self, bag: set):
        self.bag = bag

    def on_message(self, _, message):
        self.bag.add(message)


@pytest.fixture
def mock_matrix(
    monkeypatch,
    retry_interval,
    retries_before_backoff,
    local_matrix_servers,
    private_rooms,
    global_rooms,
):

    from raiden.network.transport.matrix.client import User

    monkeypatch.setattr(User, "get_display_name", lambda _: "random_display_name")

    def mock_get_user(klass, user: Union[User, str]) -> User:  # pylint: disable=unused-argument
        return User(None, USERID1)

    def mock_get_room_ids_for_address(  # pylint: disable=unused-argument
        klass, address: Address, filter_private: bool = None
    ) -> List[str]:
        return ["!roomID:server"]

    def mock_set_room_id_for_address(  # pylint: disable=unused-argument
        self, address: Address, room_id: Optional[str]
    ):
        pass

    def mock_receive_message(klass, message):  # pylint: disable=unused-argument
        # We are just unit testing the matrix transport receive so do nothing
        assert message

    config = dict(
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        server=local_matrix_servers[0],
        server_name=local_matrix_servers[0].netloc,
        available_servers=[],
        global_rooms=global_rooms,
        private_rooms=private_rooms,
    )

    transport = MatrixTransport(config)
    transport._raiden_service = MockRaidenService()
    transport._stop_event.clear()
    transport._address_mgr.add_userid_for_address(factories.HOP1, USERID1)
    transport._client.user_id = USERID0

    monkeypatch.setattr(MatrixTransport, "_get_user", mock_get_user)
    monkeypatch.setattr(
        MatrixTransport, "_get_room_ids_for_address", mock_get_room_ids_for_address
    )
    monkeypatch.setattr(MatrixTransport, "_set_room_id_for_address", mock_set_room_id_for_address)
    monkeypatch.setattr(MatrixTransport, "_receive_message", mock_receive_message)

    return transport


def ping_pong_message_success(transport0, transport1):
    queueid0 = QueueIdentifier(
        recipient=transport0._raiden_service.address,
        canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
    )

    queueid1 = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
    )

    received_messages0 = transport0._raiden_service.message_handler.bag
    received_messages1 = transport1._raiden_service.message_handler.bag

    msg_id = random.randint(1e5, 9e5)

    ping_message = Processed(message_identifier=msg_id, signature=EMPTY_SIGNATURE)
    pong_message = Delivered(delivered_message_identifier=msg_id, signature=EMPTY_SIGNATURE)

    transport0._raiden_service.sign(ping_message)
    transport1._raiden_service.sign(pong_message)
    transport0.send_async(queueid1, ping_message)

    with Timeout(40, exception=False):
        all_messages_received = False
        while not all_messages_received:
            all_messages_received = (
                ping_message in received_messages1 and pong_message in received_messages0
            )
            gevent.sleep(0.1)
    assert ping_message in received_messages1
    assert pong_message in received_messages0

    transport0._raiden_service.sign(pong_message)
    transport1._raiden_service.sign(ping_message)
    transport1.send_async(queueid0, ping_message)

    with Timeout(40, exception=False):
        all_messages_received = False
        while not all_messages_received:
            all_messages_received = (
                ping_message in received_messages0 and pong_message in received_messages1
            )
            gevent.sleep(0.1)
    assert ping_message in received_messages0
    assert pong_message in received_messages1

    return all_messages_received


def is_reachable(transport: MatrixTransport, address: Address) -> bool:
    return (
        transport._address_mgr.get_address_reachability(address) is AddressReachability.REACHABLE
    )


@pytest.fixture()
def skip_userid_validation(monkeypatch):
    import raiden.network.transport.matrix
    import raiden.network.transport.matrix.transport
    import raiden.network.transport.matrix.utils

    def mock_validate_userid_signature(user):  # pylint: disable=unused-argument
        return factories.HOP1

    monkeypatch.setattr(
        raiden.network.transport.matrix,
        "validate_userid_signature",
        mock_validate_userid_signature,
    )
    monkeypatch.setattr(
        raiden.network.transport.matrix.transport,
        "validate_userid_signature",
        mock_validate_userid_signature,
    )
    monkeypatch.setattr(
        raiden.network.transport.matrix.utils,
        "validate_userid_signature",
        mock_validate_userid_signature,
    )


def make_message(overwrite_data=None):
    room = Room(None, "!roomID:server")
    if not overwrite_data:
        message = SecretRequest(
            message_identifier=random.randint(0, UINT64_MAX),
            payment_identifier=1,
            secrethash=factories.UNIT_SECRETHASH,
            amount=1,
            expiration=10,
            signature=EMPTY_SIGNATURE,
        )
        message.sign(LocalSigner(factories.HOP1_KEY))
        data = JSONSerializer.serialize(message)
    else:
        data = overwrite_data

    event = dict(
        type="m.room.message", sender=USERID1, content={"msgtype": "m.text", "body": data}
    )
    return room, event


def test_normal_processing_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    m = mock_matrix
    room, event = make_message()
    assert m._handle_message(room, event)


def test_processing_invalid_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    m = mock_matrix
    invalid_json = '{"foo": 1,'
    room, event = make_message(overwrite_data=invalid_json)
    assert not m._handle_message(room, event)


def test_sending_nonstring_body(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    m = mock_matrix
    room, event = make_message(overwrite_data=b"somebinarydata")
    assert not m._handle_message(room, event)


@pytest.mark.parametrize(
    "message_input", ['{"this": 1, "message": 5, "is": 3, "not_valid": 5}', "["]
)
def test_processing_invalid_message_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation, message_input
):
    m = mock_matrix
    room, event = make_message(overwrite_data=message_input)
    assert not m._handle_message(room, event)


def test_processing_invalid_message_type_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    m = mock_matrix
    invalid_message = '{"_type": "NonExistentMessage", "is": 3, "not_valid": 5}'
    room, event = make_message(overwrite_data=invalid_message)
    assert not m._handle_message(room, event)


@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [2])
def test_matrix_message_sync(matrix_transports):

    transport0, transport1 = matrix_transports

    received_messages = set()

    message_handler = MessageHandler(received_messages)
    raiden_service0 = MockRaidenService(message_handler)
    raiden_service1 = MockRaidenService(message_handler)

    raiden_service1.handle_and_track_state_changes = MagicMock()

    transport0.start(raiden_service0, message_handler, None)
    transport1.start(raiden_service1, message_handler, None)

    gevent.sleep(1)

    latest_auth_data = f"{transport1._user_id}/{transport1._client.api.token}"
    update_transport_auth_data = ActionUpdateTransportAuthData(latest_auth_data)
    raiden_service1.handle_and_track_state_changes.assert_called_with([update_transport_auth_data])

    transport0.start_health_check(transport1._raiden_service.address)
    transport1.start_health_check(transport0._raiden_service.address)

    queue_identifier = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        canonical_identifier=factories.UNIT_CANONICAL_ID,
    )

    for i in range(5):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        transport0._raiden_service.sign(message)
        transport0.send_async(queue_identifier, message)
    with Timeout(40):
        while not len(received_messages) == 10:
            gevent.sleep(0.1)

    assert len(received_messages) == 10

    for i in range(5):
        assert any(getattr(m, "message_identifier", -1) == i for m in received_messages)

    transport1.stop()

    assert latest_auth_data

    # Send more messages while the other end is offline
    for i in range(10, 15):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        transport0._raiden_service.sign(message)
        transport0.send_async(queue_identifier, message)

    # Should fetch the 5 messages sent while transport1 was offline
    transport1.start(transport1._raiden_service, message_handler, latest_auth_data)

    gevent.sleep(2)

    assert len(set(received_messages)) == 20
    for i in range(10, 15):
        assert any(getattr(m, "message_identifier", -1) == i for m in received_messages)


@pytest.mark.skipif(getattr(pytest, "config").getvalue("usepdb"), reason="test fails with pdb")
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_matrix_tx_error_handling(  # pylint: disable=unused-argument
    raiden_chain, token_addresses
):
    """Proxies exceptions must be forwarded by the transport."""
    app0, app1 = raiden_chain
    token_address = token_addresses[0]

    channel_state = views.get_channelstate_for(
        chain_state=views.state_from_app(app0),
        payment_network_address=app0.raiden.default_registry.address,
        token_address=token_address,
        partner_address=app1.raiden.address,
    )
    burn_eth(app0.raiden.chain.client)

    def make_tx(*args, **kwargs):  # pylint: disable=unused-argument
        close_channel = ActionChannelClose(canonical_identifier=channel_state.canonical_identifier)
        app0.raiden.handle_and_track_state_changes([close_channel])

    app0.raiden.transport._client.add_presence_listener(make_tx)

    exception = ValueError("exception was not raised from the transport")
    with pytest.raises(InsufficientFunds), gevent.Timeout(200, exception=exception):
        app0.raiden.get()


def test_matrix_message_retry(
    local_matrix_servers, private_rooms, retry_interval, retries_before_backoff, global_rooms
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
            "global_rooms": global_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
            "private_rooms": private_rooms,
        }
    )
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(raiden_service, raiden_service.message_handler, None)
    transport.log = MagicMock()

    # Receiver is online
    transport._address_mgr._address_to_reachability[
        partner_address
    ] = AddressReachability.REACHABLE

    queueid = QueueIdentifier(
        recipient=partner_address, canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE
    )
    chain_state = raiden_service.wal.state_manager.current_state

    retry_queue: _RetryQueue = transport._get_retrier(partner_address)
    assert bool(retry_queue), "retry_queue not running"

    # Send the initial message
    message = Processed(message_identifier=0, signature=EMPTY_SIGNATURE)
    transport._raiden_service.sign(message)
    chain_state.queueids_to_queues[queueid] = [message]
    retry_queue.enqueue_global(message)

    gevent.sleep(1)

    assert transport._send_raw.call_count == 1

    # Receiver goes offline
    transport._address_mgr._address_to_reachability[
        partner_address
    ] = AddressReachability.UNREACHABLE

    gevent.sleep(retry_interval)

    transport.log.debug.assert_called_with(
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

    gevent.sleep(retry_interval)

    # Retrier now should have sent the message again
    assert transport._send_raw.call_count == 2

    transport.stop()
    transport.get()


def test_join_invalid_discovery(
    local_matrix_servers, private_rooms, retry_interval, retries_before_backoff, global_rooms
):
    """join_global_room tries to join on all servers on available_servers config

    If any of the servers isn't reachable by synapse, it'll return a 500 response, which needs
    to be handled, and if no discovery room is found on any of the available_servers, one in
    our current server should be created
    """
    transport = MatrixTransport(
        {
            "global_rooms": global_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": ["http://invalid.server"],
            "private_rooms": private_rooms,
        }
    )
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(raiden_service, raiden_service.message_handler, None)
    transport.log = MagicMock()
    discovery_room_name = make_room_alias(transport.network_id, "discovery")
    assert isinstance(transport._global_rooms.get(discovery_room_name), Room)

    transport.stop()
    transport.get()


@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [3])
@pytest.mark.skip("Issue: #4337")
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

    transport0.start(raiden_service0, message_handler0, "")
    transport1.start(raiden_service1, message_handler1, "")
    transport2.start(raiden_service2, message_handler2, "")

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
    local_matrix_servers, retries_before_backoff, retry_interval, private_rooms, global_rooms
):

    transport = MatrixTransport(
        {
            "global_rooms": global_rooms,
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0], "https://localhost:1"],
            "private_rooms": private_rooms,
        }
    )
    transport.start(MockRaidenService(None), MessageHandler(set()), "")
    gevent.sleep(0.2)

    discovery_room_name = make_room_alias(transport.network_id, "discovery")
    assert isinstance(transport._global_rooms.get(discovery_room_name), Room)

    transport.stop()
    transport.get()


def test_matrix_send_global(
    local_matrix_servers, retries_before_backoff, retry_interval, private_rooms, global_rooms
):
    transport = MatrixTransport(
        {
            "global_rooms": global_rooms + [MONITORING_BROADCASTING_ROOM],
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
            "private_rooms": private_rooms,
        }
    )
    transport.start(MockRaidenService(None), MessageHandler(set()), "")
    gevent.idle()

    ms_room_name = make_room_alias(transport.network_id, MONITORING_BROADCASTING_ROOM)
    ms_room = transport._global_rooms.get(ms_room_name)
    assert isinstance(ms_room, Room)

    ms_room.send_text = MagicMock(spec=ms_room.send_text)

    for i in range(5):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        transport._raiden_service.sign(message)
        transport.send_global(MONITORING_BROADCASTING_ROOM, message)
    transport._spawn(transport._global_send_worker)

    gevent.idle()

    assert ms_room.send_text.call_count >= 1
    # messages could have been bundled
    call_args_str = " ".join(str(arg) for arg in ms_room.send_text.call_args_list)
    for i in range(5):
        assert f'"message_identifier": "{i}"' in call_args_str

    transport.stop()
    transport.get()


def test_monitoring_global_messages(
    local_matrix_servers,
    private_rooms,
    retry_interval,
    retries_before_backoff,
    monkeypatch,
    global_rooms,
):
    """
    Test that RaidenService sends RequestMonitoring messages to global
    MONITORING_BROADCASTING_ROOM room on newly received balance proofs.
    """
    transport = MatrixTransport(
        {
            "global_rooms": global_rooms + [MONITORING_BROADCASTING_ROOM],
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
            "private_rooms": private_rooms,
        }
    )
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)
    raiden_service.config = dict(services=dict(monitoring_enabled=True))

    transport.start(raiden_service, raiden_service.message_handler, None)

    ms_room_name = make_room_alias(transport.network_id, MONITORING_BROADCASTING_ROOM)
    ms_room = transport._global_rooms.get(ms_room_name)
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
    raiden_service.user_deposit.effective_balance.return_value = 100

    update_monitoring_service_from_balance_proof(
        raiden=raiden_service,
        chain_state=None,
        new_balance_proof=balance_proof,
        monitoring_service_contract_address=bytes([1] * 20),
    )
    gevent.idle()

    with gevent.Timeout(2):
        while ms_room.send_text.call_count < 1:
            gevent.idle()
    assert ms_room.send_text.call_count == 1


@pytest.mark.parametrize("matrix_server_count", [1])
@pytest.mark.parametrize("route_mode", [RoutingMode.LOCAL, RoutingMode.PFS])
def test_pfs_global_messages(
    local_matrix_servers,
    private_rooms,
    retry_interval,
    retries_before_backoff,
    monkeypatch,
    global_rooms,
    route_mode,
):
    """
    Test that RaidenService sends PFSCapacityUpdate messages to global
    PATH_FINDING_BROADCASTING_ROOM room on newly received balance proofs.
    """
    transport = MatrixTransport(
        {
            "global_rooms": global_rooms + [PATH_FINDING_BROADCASTING_ROOM],
            "retries_before_backoff": retries_before_backoff,
            "retry_interval": retry_interval,
            "server": local_matrix_servers[0],
            "server_name": local_matrix_servers[0].netloc,
            "available_servers": [local_matrix_servers[0]],
            "private_rooms": private_rooms,
        }
    )
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)
    raiden_service.config = dict(services=dict(monitoring_enabled=True))
    raiden_service.routing_mode = route_mode

    transport.start(raiden_service, raiden_service.message_handler, None)

    pfs_room_name = make_room_alias(transport.network_id, PATH_FINDING_BROADCASTING_ROOM)
    pfs_room = transport._global_rooms.get(pfs_room_name)
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
    raiden_service.transport.send_global(PATH_FINDING_BROADCASTING_ROOM, fee_update)
    with gevent.Timeout(2):
        while pfs_room.send_text.call_count < 2:
            gevent.idle()
    assert pfs_room.send_text.call_count == 2
    msg_data = json.loads(pfs_room.send_text.call_args[0][0])
    assert msg_data["_type"] == "raiden.messages.path_finding_service.PFSFeeUpdate"

    transport.stop()
    transport.get()


@pytest.mark.parametrize(
    "private_rooms, expected_join_rule",
    [
        [[True, True], "invite"],
        [[True, False], "invite"],
        [[False, True], "public"],
        [[False, False], "public"],
    ],
)
@pytest.mark.parametrize("number_of_transports", [2])
@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.skip("Issue: #4338")
def test_matrix_invite_private_room_happy_case(matrix_transports, expected_join_rule):
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)

    transport0, transport1 = matrix_transports

    transport0.start(raiden_service0, raiden_service0.message_handler, None)
    transport1.start(raiden_service1, raiden_service1.message_handler, None)

    transport0.start_health_check(transport1._raiden_service.address)
    transport1.start_health_check(transport0._raiden_service.address)

    room_id = transport0._get_room_for_address(raiden_service1.address).room_id
    with Timeout(40):
        while True:
            try:
                room_state0 = transport0._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    join_rule0 = [
        event["content"].get("join_rule")
        for event in room_state0
        if event["type"] == "m.room.join_rules"
    ][0]

    assert join_rule0 == expected_join_rule

    with Timeout(40):
        while True:
            try:
                room_state1 = transport1._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    join_rule1 = [
        event["content"].get("join_rule")
        for event in room_state1
        if event["type"] == "m.room.join_rules"
    ][0]

    assert join_rule1 == expected_join_rule


@pytest.mark.parametrize(
    "private_rooms, expected_join_rule0, expected_join_rule1",
    [
        [[True, True], "invite", "invite"],
        [[True, False], "invite", "invite"],
        [[False, True], "public", "public"],
        [[False, False], "public", "public"],
    ],
)
@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [2])
def test_matrix_invite_private_room_unhappy_case1(
    matrix_transports, expected_join_rule0, expected_join_rule1
):
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)

    transport0, transport1 = matrix_transports

    transport0.start(raiden_service0, raiden_service0.message_handler, None)
    transport1.start(raiden_service1, raiden_service1.message_handler, None)

    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)

    room_id = transport0._get_room_for_address(raiden_service1.address).room_id
    with Timeout(40):
        while True:
            try:
                room_state0 = transport0._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    join_rule0 = [
        event["content"].get("join_rule")
        for event in room_state0
        if event["type"] == "m.room.join_rules"
    ][0]

    assert join_rule0 == expected_join_rule0

    with Timeout(40):
        while True:
            try:
                room_state1 = transport1._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    join_rule1 = [
        event["content"].get("join_rule")
        for event in room_state1
        if event["type"] == "m.room.join_rules"
    ][0]

    assert join_rule1 == expected_join_rule1


@pytest.mark.parametrize(
    "private_rooms, expected_join_rule0, expected_join_rule1",
    [
        [[True, True], "invite", "invite"],
        [[True, False], "invite", "invite"],
        [[False, True], "public", "public"],
        [[False, False], "public", "public"],
    ],
)
@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [2])
@pytest.mark.skip("Issue: #4336")
def test_matrix_invite_private_room_unhappy_case_2(
    matrix_transports, expected_join_rule0, expected_join_rule1
):
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)

    transport0, transport1 = matrix_transports

    transport0.start(raiden_service0, raiden_service0.message_handler, None)
    transport1.start(raiden_service1, raiden_service1.message_handler, None)

    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)

    assert is_reachable(transport1, raiden_service0.address)
    assert is_reachable(transport0, raiden_service1.address)

    transport1.stop()
    with Timeout(40):
        while is_reachable(transport0, raiden_service1.address):
            gevent.sleep(0.1)

    assert not is_reachable(transport0, raiden_service1.address)

    room_id = transport0._get_room_for_address(raiden_service1.address).room_id

    transport1.start(raiden_service1, raiden_service1.message_handler, None)

    with Timeout(40):
        while True:
            try:
                room_state0 = transport0._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    join_rule0 = [
        event["content"].get("join_rule")
        for event in room_state0
        if event["type"] == "m.room.join_rules"
    ][0]

    assert join_rule0 == expected_join_rule0

    with Timeout(40):
        while True:
            try:
                room_state1 = transport1._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    join_rule1 = [
        event["content"].get("join_rule")
        for event in room_state1
        if event["type"] == "m.room.join_rules"
    ][0]

    assert join_rule1 == expected_join_rule1


@pytest.mark.parametrize(
    "private_rooms, expected_join_rule",
    [
        [[True, True], "invite"],
        [[True, False], "invite"],
        [[False, True], "public"],
        [[False, False], "public"],
    ],
)
@pytest.mark.parametrize("number_of_transports", [2])
@pytest.mark.parametrize("matrix_server_count", [2])
def test_matrix_invite_private_room_unhappy_case_3(matrix_transports, expected_join_rule):
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)

    transport0, transport1 = matrix_transports

    transport0.start(raiden_service0, raiden_service0.message_handler, None)
    transport1.start(raiden_service1, raiden_service1.message_handler, None)

    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)

    assert is_reachable(transport1, raiden_service0.address)
    assert is_reachable(transport0, raiden_service1.address)
    transport1.stop()
    with Timeout(40):
        while is_reachable(transport0, raiden_service1.address):
            gevent.sleep(0.1)

    assert not is_reachable(transport0, raiden_service1.address)

    room_id = transport0._get_room_for_address(raiden_service1.address).room_id
    transport1.start(raiden_service1, raiden_service1.message_handler, None)

    transport0.stop()

    with Timeout(40):
        while True:
            try:
                room_state1 = transport1._client.api.get_room_state(room_id)
                break
            except MatrixRequestError:
                gevent.sleep(0.1)

    join_rule1 = [
        event["content"].get("join_rule")
        for event in room_state1
        if event["type"] == "m.room.join_rules"
    ][0]

    assert join_rule1 == expected_join_rule


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

    transport0.start(raiden_service0, message_handler0, "")
    transport1.start(raiden_service1, message_handler1, "")

    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)

    transport0.stop()
    with Timeout(40):
        while is_reachable(transport1, raiden_service0.address):
            gevent.sleep(0.1)

    assert not is_reachable(transport1, raiden_service0.address)

    transport2.start(raiden_service0, message_handler0, "")

    transport2.start_health_check(raiden_service1.address)

    assert ping_pong_message_success(transport2, transport1)

    transport2.stop()
    with Timeout(40):
        while is_reachable(transport1, raiden_service0.address):
            gevent.sleep(0.1)

    assert not is_reachable(transport1, raiden_service0.address)

    transport0.start(raiden_service0, message_handler0, "")
    with Timeout(40):
        while not is_reachable(transport1, raiden_service0.address):
            gevent.sleep(0.1)

    assert is_reachable(transport1, raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)


@pytest.mark.xfail(reason="XFail until raiden-network/raiden#4030 is fixed")
@pytest.mark.parametrize("matrix_server_count", [3])
@pytest.mark.parametrize("number_of_transports", [6])
def test_matrix_multi_user_roaming(matrix_transports):

    # 6 transports on 3 servers, where 0,3, 1,4, etc are one the same server
    transport0, transport1, transport2, transport3, transport4, transport5 = matrix_transports
    received_messages0 = set()
    received_messages1 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)

    raiden_service0 = MockRaidenService(message_handler0)
    raiden_service1 = MockRaidenService(message_handler1)

    # Both nodes on the same server
    transport0.start(raiden_service0, message_handler0, "")
    transport3.start(raiden_service1, message_handler1, "")

    transport0.start_health_check(raiden_service1.address)
    transport3.start_health_check(raiden_service0.address)

    assert ping_pong_message_success(transport0, transport3)

    # Node two switches to second server
    transport3.stop()

    transport4.start(raiden_service1, message_handler1, "")
    transport4.start_health_check(raiden_service0.address)
    gevent.sleep(0.5)

    assert ping_pong_message_success(transport0, transport4)

    # Node two switches to third server
    transport4.stop()

    transport5.start(raiden_service1, message_handler1, "")
    transport5.start_health_check(raiden_service0.address)
    gevent.sleep(0.5)

    assert ping_pong_message_success(transport0, transport5)
    # Node one switches to second server, Node two back to first
    transport0.stop()
    transport5.stop()
    transport1.start(raiden_service0, message_handler0, "")
    transport1.start_health_check(raiden_service1.address)
    transport3.start(raiden_service1, message_handler1, "")
    gevent.sleep(0.5)

    assert ping_pong_message_success(transport1, transport3)

    # Node two joins on second server again
    transport3.stop()

    transport4.start(raiden_service1, message_handler1, "")
    gevent.sleep(0.5)

    assert ping_pong_message_success(transport1, transport4)

    # Node two switches to third server
    transport4.stop()

    transport5.start(raiden_service1, message_handler1, "")
    gevent.sleep(0.5)

    assert ping_pong_message_success(transport1, transport5)

    # Node one switches to third server, node two switches to first server
    transport1.stop()
    transport5.stop()

    transport2.start(raiden_service0, message_handler0, "")
    transport2.start_health_check(raiden_service1.address)
    transport3.start(raiden_service1, message_handler1, "")
    gevent.sleep(0.5)

    assert ping_pong_message_success(transport2, transport3)

    # Node two switches to second server

    transport3.stop()
    transport4.start(raiden_service1, message_handler1, "")

    gevent.sleep(0.5)
    assert ping_pong_message_success(transport2, transport4)

    # Node two joins on third server

    transport4.stop()
    transport5.start(raiden_service1, message_handler1, "")

    gevent.sleep(0.5)
    assert ping_pong_message_success(transport2, transport5)


@pytest.mark.parametrize("private_rooms", [[True, True]])
@pytest.mark.parametrize("matrix_server_count", [2])
@pytest.mark.parametrize("number_of_transports", [2])
@pytest.mark.skip("Issue: #4379")
def test_reproduce_handle_invite_send_race_issue_3588(matrix_transports):
    transport0, transport1 = matrix_transports
    received_messages0 = set()
    received_messages1 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)

    raiden_service0 = MockRaidenService(message_handler0)
    raiden_service1 = MockRaidenService(message_handler1)

    transport0.start(raiden_service0, message_handler0, "")
    transport1.start(raiden_service1, message_handler1, "")

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

    transport0.start(raiden_service0, message_handler0, "")
    transport1.start(raiden_service1, message_handler1, "")

    transport0.start_health_check(raiden_service1.address)
    transport1.start_health_check(raiden_service0.address)
    message = Processed(message_identifier=1, signature=EMPTY_SIGNATURE)
    transport0._raiden_service.sign(message)
    transport0.send_to_device(raiden_service1.address, message)
    gevent.sleep(0.5)
    transport1._receive_to_device.assert_not_called()
    message = ToDevice(message_identifier=1, signature=EMPTY_SIGNATURE)
    transport0._raiden_service.sign(message)
    transport0.send_to_device(raiden_service1.address, message)
    gevent.sleep(0.5)
    transport1._receive_to_device.assert_called()
