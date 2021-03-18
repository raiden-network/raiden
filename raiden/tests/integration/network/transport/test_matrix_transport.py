import random  # pylint: skip-file  XXX-UAM remove after tests are updated
from functools import partial
from typing import Any
from unittest.mock import MagicMock, Mock

import gevent
import pytest
from eth_utils import to_normalized_address
from gevent import Timeout

import raiden
from raiden.constants import (
    BLOCK_ID_LATEST,
    DISCOVERY_DEFAULT_ROOM,
    EMPTY_SIGNATURE,
    DeviceIDs,
    Environment,
    RoutingMode,
)
from raiden.exceptions import InsufficientEth
from raiden.messages.monitoring_service import RequestMonitoring
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.messages.synchronization import Delivered, Processed
from raiden.network.transport.matrix.client import Room
from raiden.network.transport.matrix.transport import (
    MatrixTransport,
    MessagesQueue,
    _RetryQueue,
    populate_services_addresses,
)
from raiden.network.transport.matrix.utils import (
    AddressReachability,
    UserPresence,
    make_room_alias,
)
from raiden.raiden_service import RaidenService
from raiden.services import send_pfs_update, update_monitoring_service_from_balance_proof
from raiden.settings import (
    MIN_MONITORING_AMOUNT_DAI,
    MONITORING_REWARD,
    CapabilitiesConfig,
    MatrixTransportConfig,
    RaidenConfig,
    ServiceConfig,
)
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.detect_failure import expect_failure, raise_on_failure
from raiden.tests.utils.factories import (
    HOP1,
    CanonicalIdentifierProperties,
    NettingChannelEndStateProperties,
    make_privkeys_ordered,
)
from raiden.tests.utils.mocks import MockRaidenService
from raiden.tests.utils.smartcontracts import deploy_service_registry_and_set_urls
from raiden.tests.utils.transfer import wait_assert
from raiden.transfer import views
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.transfer.state import NetworkState
from raiden.transfer.state_change import ActionChannelClose
from raiden.utils.formatting import to_checksum_address
from raiden.utils.keys import privatekey_to_address
from raiden.utils.typing import Address, Dict, List
from raiden.waiting import wait_for_network_state

HOP1_BALANCE_PROOF = factories.BalanceProofSignedStateProperties(pkey=factories.HOP1_KEY)

TIMEOUT_MESSAGE_RECEIVE = 15


@pytest.fixture
def num_services():
    return 2


@pytest.fixture
def services(num_services, matrix_transports):
    service_addresses_to_expiry = {factories.make_address(): 9999 for _ in range(num_services)}
    for transport in matrix_transports:
        transport.update_services_addresses(service_addresses_to_expiry)
    return [to_normalized_address(addr) for addr in service_addresses_to_expiry.keys()]


@pytest.fixture
def number_of_transports():
    return 1


class MessageHandler:
    def __init__(self, bag: set):
        self.bag = bag

    def on_messages(self, _, messages):
        self.bag.update(messages)


def get_to_device_broadcast_messages(to_device_mock, expected_receiver_addresses, device_id):

    collected_messages = list()
    for _, kwargs in to_device_mock.call_args_list:
        assert kwargs["event_type"] == "m.room.message"
        # has to always be broadcasted to all services for each api call
        messages_batch = list()
        addresses = list()
        for address, to_device_dict in kwargs["messages"].items():
            # ignore home-server, but extract the address prefix
            addresses.append(address.split(":")[0][1:])
            assert to_device_dict.keys() == {device_id}
            messages = to_device_dict[device_id]["body"].split("\n")
            messages = [MessageSerializer.deserialize(message) for message in messages]

            if not messages_batch:
                messages_batch = messages
            else:
                assert messages_batch == messages
        assert len(addresses) == len(expected_receiver_addresses)
        assert set(addresses) == set(expected_receiver_addresses)
        collected_messages += messages_batch
    return collected_messages


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
    transport0.send_async([MessagesQueue(queueid1, [ping_message])])

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
    transport1.send_async([MessagesQueue(queueid0, [ping_message])])

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
    raise NotImplementedError
    # XXX-UAM uam was accessed here
    # return (
    #     transport._address_mgr.get_address_reachability(address) is AddressReachability.REACHABLE
    # )


def _wait_for_peer_reachability(
    transport: MatrixTransport,
    target_address: Address,
    target_reachability: AddressReachability,
    timeout: int = 5,
):
    raise NotImplementedError
    with Timeout(timeout):
        while True:
            # XXX-UAM uam was accessed here
            # peer_reachability = transport._address_mgr.get_address_reachability(target_address)
            # if peer_reachability is target_reachability:
            # break
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


@pytest.mark.skip(reason="Test is still using presence / health check")
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

    transport0.start(raiden_service0, None)
    transport1.start(raiden_service1, None)

    # XXX-UAM here was the health check before
    # transport0.immediate_health_check_for(transport1._raiden_service.address)
    # transport1.immediate_health_check_for(transport0._raiden_service.address)

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
        transport0.send_async([MessagesQueue(queue_identifier, [message])])

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

    # Send more messages while the other end is offline
    for i in range(10, 15):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        raiden0_queues[queue_identifier].append(message)
        transport0._raiden_service.sign(message)
        transport0.send_async([MessagesQueue(queue_identifier, [message])])

    # Should fetch the 5 messages sent while transport1 was offline
    transport1.start(transport1._raiden_service, None)
    # XXX-UAM here was the health check before
    # transport1.immediate_health_check_for(transport0._raiden_service.address)

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


@expect_failure
@pytest.mark.skip(reason="Test is still using presence / health check")
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
@pytest.mark.parametrize("number_of_tokens", [1])
def test_matrix_tx_error_handling(  # pylint: disable=unused-argument
    raiden_chain: List[RaidenService], token_addresses, request
):
    """Proxies exceptions must be forwarded by the transport."""
    if request.config.option.usepdb:
        pytest.skip("test fails with pdb")
    app0, app1 = raiden_chain
    token_address = token_addresses[0]

    channel_state = views.get_channelstate_for(
        chain_state=views.state_from_raiden(app0),
        token_network_registry_address=app0.default_registry.address,
        token_address=token_address,
        partner_address=app1.address,
    )
    burn_eth(app0.rpc_client)

    def make_tx(*args, **kwargs):  # pylint: disable=unused-argument
        close_channel = ActionChannelClose(canonical_identifier=channel_state.canonical_identifier)
        app0.handle_and_track_state_changes([close_channel])

    app0.transport._client.add_presence_listener(make_tx)

    exception = ValueError("Exception was not raised from the transport")
    with pytest.raises(InsufficientEth), gevent.Timeout(10, exception=exception):
        # Change presence in peer app to trigger callback in app0
        app1.transport._client.set_presence_state(UserPresence.UNAVAILABLE.value)
        app0.greenlet.get()


@pytest.mark.skip(reason="Test is still using presence / health check")
def test_matrix_message_retry(
    local_matrix_servers,
    retry_interval_initial,
    retry_interval_max,
    retries_before_backoff,
    broadcast_rooms,
):
    """Test the retry mechanism implemented into the matrix client.
    The test creates a transport and sends a message. Given that the
    receiver was online, the initial message is sent but the receiver
    doesn't respond in time and goes offline. The retrier should then
    wait for the `retry_interval` duration to pass and send the message
    again but this won't work because the receiver is offline. Once
    the receiver comes back again, the message should be sent again.
    """
    partner_address = factories.make_address()

    transport = MatrixTransport(
        config=MatrixTransportConfig(
            broadcast_rooms=broadcast_rooms,
            retries_before_backoff=retries_before_backoff,
            retry_interval_initial=retry_interval_initial,
            retry_interval_max=retry_interval_max,
            server=local_matrix_servers[0],
            available_servers=[local_matrix_servers[0]],
        ),
        environment=Environment.DEVELOPMENT,
    )
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(raiden_service, None)
    transport.log = MagicMock()

    # Receiver is online
    # XXX-UAM uam was accessed here
    # transport._address_mgr._address_to_reachabilitystate[partner_address] = ReachabilityState(
    #     AddressReachability.REACHABLE, datetime.now()
    # )

    queueid = QueueIdentifier(
        recipient=partner_address, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
    )
    chain_state = raiden_service.wal.get_current_state()

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
    # XXX-UAM uam was accessed here
    # transport._address_mgr._address_to_reachabilitystate[partner_address] = ReachabilityState(
    #     AddressReachability.UNREACHABLE, datetime.now()
    # )

    with gevent.Timeout(retry_interval_initial + 2):
        wait_assert(
            transport.log.debug.assert_called_with,
            "Partner not reachable. Skipping.",
            partner=to_checksum_address(partner_address),
            status=AddressReachability.UNREACHABLE,
        )

    # Retrier did not call send_raw given that the receiver is still offline
    assert transport._send_raw.call_count == 1

    # Receiver comes back online
    # XXX-UAM uam was accessed here
    # transport._address_mgr._address_to_reachabilitystate[partner_address] = ReachabilityState(
    #     AddressReachability.REACHABLE, datetime.now()
    # )

    # Retrier should send the message again
    with gevent.Timeout(retry_interval_initial + 2):
        while transport._send_raw.call_count != 2:
            gevent.sleep(0.1)

    transport.stop()
    transport.greenlet.get()


@pytest.mark.parametrize("matrix_server_count", [3])
@pytest.mark.parametrize("number_of_transports", [3])
def test_matrix_transport_handles_metadata(matrix_transports):

    transport0, transport1, transport2 = matrix_transports

    transport0_messages = set()
    transport1_messages = set()

    transport0_message_handler = MessageHandler(transport0_messages)
    transport1_message_handler = MessageHandler(transport1_messages)

    raiden_service0 = MockRaidenService(transport0_message_handler)
    raiden_service1 = MockRaidenService(transport1_message_handler)
    raiden_service2 = MockRaidenService()

    raiden_service1.handle_and_track_state_changes = MagicMock()

    transport0.start(raiden_service0, None)
    transport1.start(raiden_service1, None)
    transport2.start(raiden_service2, None)

    queue_identifier = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        canonical_identifier=factories.UNIT_CANONICAL_ID,
    )

    raiden0_queues = views.get_all_messagequeues(views.state_from_raiden(raiden_service0))
    raiden0_queues[queue_identifier] = []

    correct_metadata = {"user_id": transport1.user_id}
    # This is the wrong user for the chosen address (address is implicit by the queue_identifier)
    incorrect_metadata = {"user_id": transport2.user_id}
    # invalid metadata, will lead to the fallback user-id generation
    invalid_metadata = {"user_id": "invalid"}
    no_metadata = None

    all_metadata = (correct_metadata, incorrect_metadata, invalid_metadata, no_metadata)
    num_sends = 2
    message_id = 0

    for _ in range(num_sends):
        for metadata in all_metadata:
            message = Processed(message_identifier=message_id, signature=EMPTY_SIGNATURE)
            raiden0_queues[queue_identifier].append(message)
            transport0._raiden_service.sign(message)
            message_queues = [MessagesQueue(queue_identifier, [(message, metadata)])]
            transport0.send_async(message_queues)
            message_id += 1

    num_expected_messages = 3 * num_sends
    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while len(transport0_messages) < num_expected_messages:
            gevent.sleep(0.1)

        while len(transport1_messages) < num_expected_messages:
            gevent.sleep(0.1)

    # TODO also track / assert the number of to-device messages
    #  and account for fallback user-ids and wrong user-ids!!
    #  Because we have multiple messages per user-id (num_sends),
    #  the calls to-device should be reduced per user-id because of batching

    # transport1 receives the `Processed` messages sent by transport0
    for i in range(num_expected_messages):
        assert any(m.message_identifier == i for m in transport1_messages)

    # transport0 answers with a `Delivered` for each `Processed`
    for i in range(num_expected_messages):
        assert any(m.delivered_message_identifier == i for m in transport0_messages)

    transport0.stop()
    transport1.stop()
    transport2.stop()


def test_join_invalid_discovery(
    local_matrix_servers,
    retry_interval_initial,
    retry_interval_max,
    retries_before_backoff,
    broadcast_rooms,
):
    """join_broadcast_room tries to join on all servers on available_servers config

    If any of the servers isn't reachable by synapse, it'll return a 500 response, which needs
    to be handled, and if no discovery room is found on any of the available_servers, one in
    our current server should be created
    """
    transport = MatrixTransport(
        config=MatrixTransportConfig(
            broadcast_rooms=broadcast_rooms,
            retries_before_backoff=retries_before_backoff,
            retry_interval_initial=retry_interval_initial,
            retry_interval_max=retry_interval_max,
            server=local_matrix_servers[0],
            available_servers=["http://invalid.server"],
        ),
        environment=Environment.DEVELOPMENT,
    )
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(raiden_service, None)
    transport.log = MagicMock()
    discovery_room_name = make_room_alias(transport.chain_id, "discovery")
    assert isinstance(transport.broadcast_rooms.get(discovery_room_name), Room)

    transport.stop()
    transport.greenlet.get()


@pytest.mark.skip(reason="Test is still using presence / health check")
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

    transport0.start(raiden_service0, "")
    transport1.start(raiden_service1, "")
    transport2.start(raiden_service2, "")

    # XXX-UAM here was the health check before
    # transport0.immediate_health_check_for(raiden_service1.address)
    # transport0.immediate_health_check_for(raiden_service2.address)
    #
    # transport1.immediate_health_check_for(raiden_service0.address)
    # transport1.immediate_health_check_for(raiden_service2.address)

    # transport2.immediate_health_check_for(raiden_service0.address)
    # transport2.immediate_health_check_for(raiden_service1.address)

    assert ping_pong_message_success(transport0, transport1)
    assert ping_pong_message_success(transport0, transport2)
    assert ping_pong_message_success(transport1, transport0)
    assert ping_pong_message_success(transport1, transport2)
    assert ping_pong_message_success(transport2, transport0)
    assert ping_pong_message_success(transport2, transport1)


def test_matrix_discovery_room_offline_server(
    local_matrix_servers,
    retries_before_backoff,
    retry_interval_initial,
    retry_interval_max,
    broadcast_rooms,
):

    transport = MatrixTransport(
        config=MatrixTransportConfig(
            broadcast_rooms=broadcast_rooms,
            retries_before_backoff=retries_before_backoff,
            retry_interval_initial=retry_interval_initial,
            retry_interval_max=retry_interval_max,
            server=local_matrix_servers[0],
            available_servers=[local_matrix_servers[0], "https://localhost:1"],
        ),
        environment=Environment.DEVELOPMENT,
    )
    transport.start(MockRaidenService(None), "")

    discovery_room_name = make_room_alias(transport.chain_id, "discovery")
    with gevent.Timeout(1):
        while not isinstance(transport.broadcast_rooms.get(discovery_room_name), Room):
            gevent.sleep(0.1)

    transport.stop()
    transport.greenlet.get()


@pytest.mark.parametrize("device_id", (DeviceIDs.PFS, DeviceIDs.MS))
def test_matrix_broadcast(matrix_transports, services, device_id):

    transport = matrix_transports[0]
    matrix_api = transport._client.api
    matrix_api.send_to_device = MagicMock(autospec=True)

    transport.start(MockRaidenService(None), "")
    gevent.idle()

    sent_messages = list()
    for i in range(5):
        message = Processed(message_identifier=i, signature=EMPTY_SIGNATURE)
        transport._raiden_service.sign(message)
        sent_messages.append(message)
        transport.broadcast(message, device_id=device_id)
    transport._schedule_new_greenlet(transport._broadcast_worker)

    gevent.idle()

    messages = get_to_device_broadcast_messages(
        matrix_api.send_to_device, services, device_id.value
    )
    assert messages == sent_messages


@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_monitoring_broadcast_messages(
    matrix_transports,
    environment_type,
    services,
    monkeypatch,
):
    """
    Test that RaidenService broadcast RequestMonitoring messages to
    MONITORING_BROADCASTING_ROOM room on newly received balance proofs.
    """

    transport = matrix_transports[0]
    matrix_api = transport._client.api
    matrix_api.retry_timeout = 0
    matrix_api.send_to_device = MagicMock(autospec=True)

    raiden_service = MockRaidenService(None)
    raiden_service.config = RaidenConfig(
        chain_id=1234,
        environment_type=environment_type,
        services=ServiceConfig(monitoring_enabled=True),
    )

    transport.start(raiden_service, None)

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
    raiden_service.default_user_deposit.effective_balance.return_value = MONITORING_REWARD

    update_monitoring_service_from_balance_proof(
        raiden=raiden_service,
        chain_state=None,
        new_balance_proof=balance_proof,
        non_closing_participant=HOP1,
    )
    gevent.idle()

    with gevent.Timeout(2):
        while matrix_api.send_to_device.call_count < 1:
            gevent.idle()
    assert matrix_api.send_to_device.call_count == 1
    messages = get_to_device_broadcast_messages(
        matrix_api.send_to_device, services, DeviceIDs.MS.value
    )
    assert len(messages) == 1
    assert isinstance(messages[0], RequestMonitoring)


@pytest.mark.parametrize("environment_type", [Environment.PRODUCTION])
@pytest.mark.parametrize(
    "channel_balance_dai, expected_messages",
    [[MIN_MONITORING_AMOUNT_DAI - 1, 0], [MIN_MONITORING_AMOUNT_DAI, 1]],
)
def test_monitoring_broadcast_messages_in_production_if_bigger_than_threshold(
    matrix_transports,
    services,
    monkeypatch,
    channel_balance_dai,
    expected_messages,
    environment_type,
):
    """
    Test that in PRODUCTION on DAI and WETH RaidenService broadcast RequestMonitoring messages
    to MONITORING_BROADCASTING_ROOM room on newly received balance proofs only when
    min threshold of channel balance is met
    """
    transport = matrix_transports[0]
    matrix_api = transport._client.api
    matrix_api.retry_timeout = 0
    matrix_api.send_to_device = MagicMock(autospec=True)

    raiden_service = MockRaidenService(None)
    raiden_service.config = RaidenConfig(
        chain_id=1234,
        environment_type=environment_type,
        services=ServiceConfig(monitoring_enabled=True),
    )

    transport.start(raiden_service, None)

    raiden_service.transport = transport
    transport.log = MagicMock()

    fake_dai_token_network = factories.make_token_network_address()
    HOP1_BALANCE_PROOF_DAI = factories.BalanceProofSignedStateProperties(
        pkey=factories.HOP1_KEY,
        canonical_identifier=factories.create(
            CanonicalIdentifierProperties(token_network_address=fake_dai_token_network)
        ),
    )

    balance_proof = factories.create(HOP1_BALANCE_PROOF_DAI)
    channel_state = factories.create(
        factories.NettingChannelStateProperties(
            canonical_identifier=CanonicalIdentifierProperties(
                token_network_address=fake_dai_token_network
            ),
            our_state=NettingChannelEndStateProperties(balance=channel_balance_dai),
        )
    )
    channel_state.our_state.balance_proof = balance_proof
    channel_state.partner_state.balance_proof = balance_proof
    monkeypatch.setattr(
        raiden.transfer.views,
        "get_channelstate_by_canonical_identifier",
        lambda *a, **kw: channel_state,
    )
    monkeypatch.setattr(
        raiden.transfer.views,
        "get_token_network_address_by_token_address",
        lambda *a, **kw: fake_dai_token_network,
    )

    raiden_service.default_user_deposit.effective_balance.return_value = MONITORING_REWARD

    update_monitoring_service_from_balance_proof(
        raiden=raiden_service,
        chain_state=None,
        new_balance_proof=balance_proof,
        non_closing_participant=HOP1,
    )
    # need a sleep here because it might take some time until message reaches room
    gevent.sleep(2)

    messages = get_to_device_broadcast_messages(
        matrix_api.send_to_device, services, DeviceIDs.MS.value
    )
    assert len(messages) == expected_messages
    if expected_messages >= 1:
        assert isinstance(messages[0], RequestMonitoring)


@pytest.mark.parametrize("matrix_server_count", [1])
def test_pfs_broadcast_messages(
    matrix_transports,
    services,
    monkeypatch,
):
    """
    Test that RaidenService broadcasts PFSCapacityUpdate messages to
    all service addresses via to-device multicast
    """
    transport = matrix_transports[0]
    matrix_api = transport._client.api
    matrix_api.retry_timeout = 0
    matrix_api.send_to_device = MagicMock(autospec=True)

    raiden_service = MockRaidenService(None)
    raiden_service.config.services.monitoring_enabled = True
    raiden_service.routing_mode = RoutingMode.PFS

    transport.start(raiden_service, None)

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
        while matrix_api.send_to_device.call_count < 1:
            gevent.idle()
    assert matrix_api.send_to_device.call_count == 1

    # send PFSFeeUpdate
    channel_state = factories.create(factories.NettingChannelStateProperties())
    fee_update = PFSFeeUpdate.from_channel_state(channel_state)
    fee_update.sign(raiden_service.signer)
    raiden_service.transport.broadcast(fee_update, device_id=DeviceIDs.PFS)

    with gevent.Timeout(2):
        while matrix_api.send_to_device.call_count < 2:
            gevent.idle()
    assert matrix_api.send_to_device.call_count == 2

    messages = get_to_device_broadcast_messages(
        matrix_api.send_to_device, services, DeviceIDs.PFS.value
    )

    assert len(messages) == 2
    assert isinstance(messages[0], PFSCapacityUpdate)
    assert isinstance(messages[1], PFSFeeUpdate)


@pytest.mark.skip(reason="Test is still using presence / health check")
@pytest.mark.parametrize("matrix_server_count", [3])
@pytest.mark.parametrize("number_of_transports", [3])
@pytest.mark.parametrize(
    "roaming_peer",
    [pytest.param("high", id="roaming_high"), pytest.param("low", id="roaming_low")],
)
def test_matrix_user_roaming(matrix_transports, roaming_peer):
    transport0, transport1, transport2 = matrix_transports
    received_messages0 = set()
    received_messages1 = set()

    message_handler0 = MessageHandler(received_messages0)
    message_handler1 = MessageHandler(received_messages1)

    reverse_privkey_order = roaming_peer == "low"
    privkey0, privkey1 = make_privkeys_ordered(count=2, reverse=reverse_privkey_order)

    raiden_service0 = MockRaidenService(message_handler0, private_key=privkey0)
    raiden_service1 = MockRaidenService(message_handler1, private_key=privkey1)

    transport0.start(raiden_service0, "")
    transport1.start(raiden_service1, "")

    # XXX-UAM here was the health check before
    # transport0.immediate_health_check_for(raiden_service1.address)
    # transport1.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)

    transport0.stop()

    wait_for_peer_unreachable(transport1, raiden_service0.address)
    assert not is_reachable(transport1, raiden_service0.address)

    transport2.start(raiden_service0, "")
    # XXX-UAM here was the health check before
    # transport2.immediate_health_check_for(raiden_service1.address)

    assert ping_pong_message_success(transport2, transport1)

    transport2.stop()

    wait_for_peer_unreachable(transport1, raiden_service0.address)
    assert not is_reachable(transport1, raiden_service0.address)

    transport0.start(raiden_service0, "")

    # XXX-UAM here was the health check before
    # transport0.immediate_health_check_for(raiden_service1.address)

    with Timeout(TIMEOUT_MESSAGE_RECEIVE):
        while not is_reachable(transport1, raiden_service0.address):
            gevent.sleep(0.1)

    assert is_reachable(transport1, raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)


@pytest.mark.skip(reason="Test is still using presence / health check")
@pytest.mark.parametrize("matrix_server_count", [3])
@pytest.mark.parametrize("number_of_transports", [6])
@pytest.mark.parametrize(
    "roaming_peer",
    [pytest.param("high", id="roaming_high"), pytest.param("low", id="roaming_low")],
)
@pytest.mark.parametrize("capabilities", [CapabilitiesConfig(to_device=True)])
def test_matrix_multi_user_roaming(matrix_transports, roaming_peer):
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

    reverse_privkey_order = roaming_peer == "low"
    privkey0, privkey1 = make_privkeys_ordered(count=2, reverse=reverse_privkey_order)

    raiden_service0 = MockRaidenService(message_handler0, private_key=privkey0)
    raiden_service1 = MockRaidenService(message_handler1, private_key=privkey1)

    # Both nodes on the same server
    transport_rs0_0.start(raiden_service0, "")
    transport_rs1_0.start(raiden_service1, "")

    # XXX-UAM here was the health check before
    # transport_rs0_0.immediate_health_check_for(raiden_service1.address)
    # transport_rs1_0.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_0, transport_rs1_0)

    # Node two switches to second server
    transport_rs1_0.stop()
    wait_for_peer_unreachable(transport_rs0_0, raiden_service1.address)

    transport_rs1_1.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport_rs1_1.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_0, transport_rs1_1)

    # Node two switches to third server
    transport_rs1_1.stop()
    wait_for_peer_unreachable(transport_rs0_0, raiden_service1.address)

    transport_rs1_2.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport_rs1_2.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_0, transport_rs1_2)
    # Node one switches to second server, Node two back to first
    transport_rs0_0.stop()
    transport_rs1_2.stop()

    transport_rs0_1.start(raiden_service0, "")
    transport_rs1_0.start(raiden_service1, "")

    # XXX-UAM here was the health check before
    # transport_rs0_1.immediate_health_check_for(raiden_service1.address)
    # transport_rs1_0.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_1, transport_rs1_0)

    # Node two joins on second server again
    transport_rs1_0.stop()
    wait_for_peer_unreachable(transport_rs0_1, raiden_service1.address)

    transport_rs1_1.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport_rs1_1.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_1, transport_rs1_1)

    # Node two switches to third server
    transport_rs1_1.stop()
    wait_for_peer_unreachable(transport_rs0_1, raiden_service1.address)

    transport_rs1_2.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport_rs1_2.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_1, transport_rs1_2)

    # Node one switches to third server, node two switches to first server
    transport_rs0_1.stop()
    transport_rs1_2.stop()

    transport_rs0_2.start(raiden_service0, "")
    # XXX-UAM here was the health check before
    # transport_rs0_2.immediate_health_check_for(raiden_service1.address)
    transport_rs1_0.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport_rs1_0.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_2, transport_rs1_0)

    # Node two switches to second server
    transport_rs1_0.stop()
    wait_for_peer_unreachable(transport_rs0_2, raiden_service1.address)

    transport_rs1_1.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport_rs1_1.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_2, transport_rs1_1)

    # Node two joins on third server
    transport_rs1_1.stop()
    wait_for_peer_unreachable(transport_rs0_2, raiden_service1.address)

    transport_rs1_2.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport_rs1_2.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport_rs0_2, transport_rs1_2)


@pytest.mark.skip(reason="Test is still using presence / health check")
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

    transport0.start(raiden_service0, "")
    transport1.start(raiden_service1, "")
    # XXX-UAM here was the health check before
    # transport0.immediate_health_check_for(raiden_service1.address)
    # transport1.immediate_health_check_for(raiden_service0.address)

    assert ping_pong_message_success(transport0, transport1)


@pytest.mark.parametrize("number_of_transports", [3])
@pytest.mark.parametrize("matrix_server_count", [1])
@pytest.mark.parametrize("matrix_sync_timeout", [5_000])  # Shorten sync timeout to prevent timeout
def test_transport_does_not_receive_broadcast_rooms_updates(matrix_transports):
    """Ensure that matrix server-side filters take effect on sync for broadcast room content.

    Although broadcasting messages in rooms is not supported by raiden anymore,
    we need this test to make sure that the sync filters for filtering out messages
    in the discovery room work.

    The test sets up 3 transports where:
    Transport0 sends a message to the discovery broadcast room.
    Transport1 has an active sync filter ID that filters out broadcast room messages.
    Transport2 has NO active sync filter so it receives everything.

    The test should wait for Transport0 to send a message and then
    verify that Transport2 has received the message while Transport1
    did not.
    """
    raiden_service0 = MockRaidenService(None)
    raiden_service1 = MockRaidenService(None)
    raiden_service2 = MockRaidenService(None)

    transport0, transport1, transport2 = matrix_transports

    received_sync_events: Dict[str, List[Dict[str, Any]]] = {"t1": [], "t2": []}

    def _handle_responses(
        name: str, responses: List[Dict[str, Any]], first_sync: bool = False
    ):  # pylint: disable=unused-argument
        for response in responses:
            joined_rooms = response.get("rooms", {}).get("join", {})
            for joined_room in joined_rooms.values():
                timeline_events = joined_room.get("timeline").get("events", [])
                message_events = [
                    event for event in timeline_events if event["type"] == "m.room.message"
                ]
                received_sync_events[name].extend(message_events)

    # Replace the transport's handle_response method
    # Should be able to detect if sync delivered a message
    transport1._client._handle_responses = partial(_handle_responses, "t1")
    transport2._client._handle_responses = partial(_handle_responses, "t2")

    transport0.start(raiden_service0, None)
    transport1.start(raiden_service1, None)
    transport2.start(raiden_service2, None)

    discovery_room_alias = make_room_alias(transport0.chain_id, DISCOVERY_DEFAULT_ROOM)
    discovery_broadcast_room_t0 = transport0.broadcast_rooms[discovery_room_alias]

    # Get the sync helper to control flow of asynchronous syncs
    sync_progress1 = transport1._client.sync_progress
    sync_progress2 = transport2._client.sync_progress

    # Reset transport2 sync filter identifier so that
    # we can receive broadcast messages
    assert transport2._client._sync_filter_id is not None
    transport2._client._sync_filter_id = None

    # get the last sync tokens to control the processed state later
    last_synced_token1 = sync_progress1.last_synced
    # for T2 we need to make sure that the current sync used the filter reset -> wait()
    last_synced_token2 = sync_progress2.synced_event.wait()[0]
    # Send another message to the broadcast room, if transport1 listens on the room it will
    # throw an exception
    message = Processed(message_identifier=1, signature=EMPTY_SIGNATURE)
    message_text = MessageSerializer.serialize(message)
    discovery_broadcast_room_t0.send_text(message_text)

    # wait for the current tokens to be processed + 1 additional sync
    # this must be done because the message should be in the sync after the stored token
    sync_progress1.wait_for_processed(last_synced_token1, 1)
    sync_progress2.wait_for_processed(last_synced_token2, 1)

    # Transport2 should have received the message
    assert received_sync_events["t2"]
    event_body = received_sync_events["t2"][0]["content"]["body"]
    assert message_text == event_body

    # Transport1 used the filter so nothing was received
    assert not received_sync_events["t1"]


@raise_on_failure
@pytest.mark.skip(reason="Test is still using presence / health check")
@pytest.mark.parametrize("matrix_server_count", [3])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_transport_presence_updates(
    raiden_network: List[RaidenService], restart_node, retry_timeout
):
    """
    Create transports and test that matrix delivers presence updates
    in the presence of filters which ignore all event updates
    from matrix for broadcast rooms except for the presence events.
    """

    app0, app1, app2 = raiden_network

    # XXX-UAM here was the health check before
    # app0.transport.immediate_health_check_for(app1.address)
    # app0.transport.immediate_health_check_for(app2.address)
    #
    # app1.transport.immediate_health_check_for(app0.address)
    # app1.transport.immediate_health_check_for(app2.address)
    #
    # app2.transport.immediate_health_check_for(app0.address)
    # app2.transport.immediate_health_check_for(app1.address)

    wait_for_network_state(app0, app1.address, NetworkState.REACHABLE, retry_timeout)
    wait_for_network_state(app0, app2.address, NetworkState.REACHABLE, retry_timeout)

    wait_for_network_state(app1, app0.address, NetworkState.REACHABLE, retry_timeout)
    wait_for_network_state(app1, app2.address, NetworkState.REACHABLE, retry_timeout)

    wait_for_network_state(app2, app0.address, NetworkState.REACHABLE, retry_timeout)
    wait_for_network_state(app2, app1.address, NetworkState.REACHABLE, retry_timeout)

    # Stop app0
    app0.stop()
    wait_for_network_state(app1, app0.address, NetworkState.UNREACHABLE, retry_timeout)
    wait_for_network_state(app2, app0.address, NetworkState.UNREACHABLE, retry_timeout)

    # Restart app0
    restart_node(app0)
    # XXX-UAM here was the health check before
    # app0.transport.immediate_health_check_for(app1.address)
    # app0.transport.immediate_health_check_for(app2.address)
    wait_for_network_state(app1, app0.address, NetworkState.REACHABLE, retry_timeout)
    wait_for_network_state(app2, app0.address, NetworkState.REACHABLE, retry_timeout)

    # Stop app1
    app1.stop()
    wait_for_network_state(app0, app1.address, NetworkState.UNREACHABLE, retry_timeout)
    wait_for_network_state(app2, app1.address, NetworkState.UNREACHABLE, retry_timeout)

    # Restart app1
    restart_node(app1)
    # XXX-UAM here was the health check before
    # app1.transport.immediate_health_check_for(app0.address)
    # app1.transport.immediate_health_check_for(app2.address)
    wait_for_network_state(app0, app1.address, NetworkState.REACHABLE, retry_timeout)
    wait_for_network_state(app2, app1.address, NetworkState.REACHABLE, retry_timeout)

    # Stop app2
    app2.stop()
    wait_for_network_state(app0, app2.address, NetworkState.UNREACHABLE, retry_timeout)
    wait_for_network_state(app1, app2.address, NetworkState.UNREACHABLE, retry_timeout)

    # Restart app0
    app2.start()
    # XXX-UAM here was the health check before
    # app2.transport.immediate_health_check_for(app0.address)
    # app2.transport.immediate_health_check_for(app1.address)
    wait_for_network_state(app0, app2.address, NetworkState.REACHABLE, retry_timeout)
    wait_for_network_state(app1, app2.address, NetworkState.REACHABLE, retry_timeout)


@raise_on_failure
@pytest.mark.skip(reason="Test is still using presence / health check")
@pytest.mark.parametrize("matrix_server_count", [1])
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("adhoc_capability", [True])
def test_transport_capabilities(raiden_network: List[RaidenService], capabilities, retry_timeout):
    """
    Test that raiden matrix users have the `avatar_url` set in a format understood
    by the capabilities parser.
    """
    app0, app1 = raiden_network

    # XXX-UAM here was the health check before
    # app0.transport.immediate_health_check_for(app1.address)
    # app1.transport.immediate_health_check_for(app0.address)

    wait_for_network_state(app0, app1.address, NetworkState.REACHABLE, retry_timeout)
    wait_for_network_state(app1, app0.address, NetworkState.REACHABLE, retry_timeout)

    # expected_capabilities = capconfig_to_dict(capabilities)

    # XXX-UAM: get_user_ids_for_address was called here
    # app1_user_ids = app0.transport.get_user_ids_for_address(app1.address)
    # assert len(app1_user_ids) == 1, "app1 should have exactly one user_id"
    # app1_user = app0.transport._client.get_user(app1_user_ids.pop())
    # app1_avatar_url = app1_user.get_avatar_url()
    # assert len(app1_avatar_url), "avatar_url not set for app1"
    # app1_capabilities = deserialize_capabilities(app1_avatar_url)
    # assert "adhoc_capability" in app1_capabilities, "capabilities could not be parsed correctly"

    # XXX-UAM uam was accessed here
    # collected_capabilities = app0.transport._address_mgr.get_address_capabilities(app1.address)
    # msg = "capabilities were not collected in transport client"
    # assert collected_capabilities == PeerCapabilities(expected_capabilities), msg


def test_populate_services_addresses(
    service_registry_address, private_keys, web3, contract_manager
):
    """
    Test 'populate_services_addresses' parsing addresses from service_registry_contract.
    """
    c1_service_proxy, _ = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    addresses = [privatekey_to_address(key) for key in private_keys]
    transport = Mock()
    populate_services_addresses(
        transport=transport, service_registry=c1_service_proxy, block_identifier=BLOCK_ID_LATEST
    )
    registered_services = list(transport.update_services_addresses.call_args[0][0].keys())
    assert len(registered_services) == 3
    assert sorted(addresses) == sorted(registered_services)
