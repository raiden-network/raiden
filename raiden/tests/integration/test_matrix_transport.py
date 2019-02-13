import json
import random
from unittest.mock import MagicMock

import gevent
import pytest
from gevent import Timeout

from raiden.constants import MONITORING_BROADCASTING_ROOM, UINT64_MAX
from raiden.messages import Processed, SecretRequest
from raiden.network.transport.matrix import MatrixTransport, UserPresence, _RetryQueue
from raiden.network.transport.matrix.client import Room
from raiden.network.transport.matrix.utils import make_room_alias
from raiden.raiden_event_handler import RaidenMonitoringEventHandler
from raiden.tests.utils.factories import HOP1, HOP1_KEY, UNIT_SECRETHASH, make_address
from raiden.tests.utils.messages import make_balance_proof
from raiden.tests.utils.mocks import MockRaidenService
from raiden.transfer.mediated_transfer.events import (
    CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    EventNewBalanceProofReceived,
)
from raiden.transfer.queue_identifier import QueueIdentifier
from raiden.transfer.state_change import ActionUpdateTransportAuthData
from raiden.utils import pex
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import Address, List, Optional, Union

USERID1 = '@Alice:Wonderland'


# All tests in this module require matrix
pytestmark = pytest.mark.usefixtures('skip_if_not_matrix')


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
):

    from raiden.network.transport.matrix.client import User
    monkeypatch.setattr(User, 'get_display_name', lambda _: 'random_display_name')

    def mock_get_user(klass, user: Union[User, str]) -> User:
        return User(None, USERID1)

    def mock_get_room_ids_for_address(
            klass,
            address: Address,
            filter_private: bool = None,
    ) -> List[str]:
        return ['!roomID:server']

    def mock_set_room_id_for_address(self, address: Address, room_id: Optional[str]):
        pass

    def mock_receive_message(klass, message):
        # We are just unit testing the matrix transport receive so do nothing
        assert message

    config = dict(
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        server=local_matrix_servers[0],
        server_name=local_matrix_servers[0].netloc,
        available_servers=[],
        global_rooms=['discovery'],
        private_rooms=private_rooms,
    )

    transport = MatrixTransport(config)
    transport._raiden_service = MockRaidenService()
    transport._stop_event.clear()
    transport._address_to_userids[HOP1] = USERID1

    monkeypatch.setattr(MatrixTransport, '_get_user', mock_get_user)
    monkeypatch.setattr(
        MatrixTransport,
        '_get_room_ids_for_address',
        mock_get_room_ids_for_address,
    )
    monkeypatch.setattr(MatrixTransport, '_set_room_id_for_address', mock_set_room_id_for_address)
    monkeypatch.setattr(MatrixTransport, '_receive_message', mock_receive_message)

    return transport


@pytest.fixture()
def skip_userid_validation(monkeypatch):
    import raiden.network.transport.matrix
    import raiden.network.transport.matrix.transport
    import raiden.network.transport.matrix.utils

    def mock_validate_userid_signature(user):
        return HOP1

    monkeypatch.setattr(
        raiden.network.transport.matrix,
        'validate_userid_signature',
        mock_validate_userid_signature,
    )
    monkeypatch.setattr(
        raiden.network.transport.matrix.transport,
        'validate_userid_signature',
        mock_validate_userid_signature,
    )
    monkeypatch.setattr(
        raiden.network.transport.matrix.utils,
        'validate_userid_signature',
        mock_validate_userid_signature,
    )


def make_message(convert_to_hex: bool = False, overwrite_data=None):
    from matrix_client.room import Room
    room = Room(None, '!roomID:server')
    if not overwrite_data:
        message = SecretRequest(
            message_identifier=random.randint(0, UINT64_MAX),
            payment_identifier=1,
            secrethash=UNIT_SECRETHASH,
            amount=1,
            expiration=10,
        )
        message.sign(LocalSigner(HOP1_KEY))
        data = message.encode()
        if convert_to_hex:
            data = '0x' + data.hex()
        else:
            data = json.dumps(message.to_dict())
    else:
        data = overwrite_data

    event = dict(
        type='m.room.message',
        sender=USERID1,
        content={
            'msgtype': 'm.text',
            'body': data,
        },
    )
    return room, event


def test_normal_processing_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    assert m._handle_message(room, event)


def test_normal_processing_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=False)
    assert m._handle_message(room, event)


def test_processing_invalid_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    invalid_json = '{"foo": 1,'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_json)
    assert not m._handle_message(room, event)


def test_sending_nonstring_body(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(overwrite_data=b'somebinarydata')
    assert not m._handle_message(room, event)


def test_processing_invalid_message_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    invalid_message = '{"this": 1, "message": 5, "is": 3, "not_valid": 5}'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_message)
    assert not m._handle_message(room, event)


def test_processing_invalid_message_cmdid_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    invalid_message = '{"type": "NonExistentMessage", "is": 3, "not_valid": 5}'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_message)
    assert not m._handle_message(room, event)


def test_processing_invalid_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = old_data[:-1]
    assert not m._handle_message(room, event)


def test_processing_invalid_message_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = old_data[:-4]
    assert not m._handle_message(room, event)


def test_processing_invalid_message_cmdid_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = '0xff' + old_data[4:]
    assert not m._handle_message(room, event)


def test_matrix_message_sync(
        local_matrix_servers,
        private_rooms,
        retry_interval,
        retries_before_backoff,
):
    transport0 = MatrixTransport({
        'global_rooms': ['discovery'],
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_servers[0],
        'server_name': local_matrix_servers[0].netloc,
        'available_servers': [],
        'private_rooms': private_rooms,
    })
    transport1 = MatrixTransport({
        'global_rooms': ['discovery'],
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_servers[0],
        'server_name': local_matrix_servers[0].netloc,
        'available_servers': [],
        'private_rooms': private_rooms,
    })

    latest_auth_data = None

    received_messages = set()

    message_handler = MessageHandler(received_messages)
    raiden_service0 = MockRaidenService(message_handler)
    raiden_service1 = MockRaidenService(message_handler)

    raiden_service1.handle_state_change = MagicMock()

    transport0.start(
        raiden_service0,
        message_handler,
        None,
    )
    transport1.start(
        raiden_service1,
        message_handler,
        None,
    )

    gevent.sleep(1)

    latest_auth_data = f'{transport1._user_id}/{transport1._client.api.token}'
    update_transport_auth_data = ActionUpdateTransportAuthData(latest_auth_data)
    raiden_service1.handle_state_change.assert_called_with(update_transport_auth_data)

    transport0.start_health_check(transport1._raiden_service.address)
    transport1.start_health_check(transport0._raiden_service.address)

    queue_identifier = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        channel_identifier=1,
    )

    for i in range(5):
        message = Processed(i)
        transport0._raiden_service.sign(message)
        transport0.send_async(
            queue_identifier,
            message,
        )

    gevent.sleep(2)

    assert len(received_messages) == 10
    for i in range(5):
        assert any(getattr(m, 'message_identifier', -1) == i for m in received_messages)

    transport1.stop()

    assert latest_auth_data

    # Send more messages while the other end is offline
    for i in range(10, 15):
        message = Processed(i)
        transport0._raiden_service.sign(message)
        transport0.send_async(
            queue_identifier,
            message,
        )

    # Should fetch the 5 messages sent while transport1 was offline
    transport1.start(
        transport1._raiden_service,
        message_handler,
        latest_auth_data,
    )

    gevent.sleep(2)

    assert len(set(received_messages)) == 20
    for i in range(10, 15):
        assert any(getattr(m, 'message_identifier', -1) == i for m in received_messages)

    transport0.stop()
    transport1.stop()
    transport0.get()
    transport1.get()


def test_matrix_message_retry(
        local_matrix_servers,
        private_rooms,
        retry_interval,
        retries_before_backoff,
):
    """ Test the retry mechanism implemented into the matrix client.
    The test creates a transport and sends a message. Given that the
    receiver was online, the initial message is sent but the receiver
    doesn't respond in time and goes offline. The retrier should then
    wait for the `retry_interval` duration to pass and send the message
    again but this won't work because the receiver is offline. Once
    the receiver comes back again, the message should be sent again.
    """
    partner_address = make_address()

    transport = MatrixTransport({
        'global_rooms': ['discovery'],
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_servers[0],
        'server_name': local_matrix_servers[0].netloc,
        'available_servers': [],
        'private_rooms': private_rooms,
    })
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(
        raiden_service,
        raiden_service.message_handler,
        None,
    )
    transport.log = MagicMock()

    # Receiver is online
    transport._address_to_presence[partner_address] = UserPresence.ONLINE

    queueid = QueueIdentifier(
        recipient=partner_address,
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    )
    chain_state = raiden_service.wal.state_manager.current_state

    retry_queue: _RetryQueue = transport._get_retrier(partner_address)
    assert bool(retry_queue), 'retry_queue not running'

    # Send the initial message
    message = Processed(0)
    transport._raiden_service.sign(message)
    chain_state.queueids_to_queues[queueid] = [message]
    retry_queue.enqueue_global(message)

    gevent.sleep(1)

    transport._send_raw.call_count = 1

    # Receiver goes offline
    transport._address_to_presence[partner_address] = UserPresence.OFFLINE

    gevent.sleep(retry_interval)

    transport.log.debug.assert_called_with(
        'Partner not reachable. Skipping.',
        partner=pex(partner_address),
        status=UserPresence.OFFLINE,
    )

    # Retrier did not call send_raw given that the receiver is still offline
    assert transport._send_raw.call_count == 1

    # Receiver comes back online
    transport._address_to_presence[partner_address] = UserPresence.ONLINE

    gevent.sleep(retry_interval)

    # Retrier now should have sent the message again
    assert transport._send_raw.call_count == 2

    transport.stop()
    transport.get()


def test_join_invalid_discovery(
        local_matrix_servers,
        private_rooms,
        retry_interval,
        retries_before_backoff,
):
    """join_global_room tries to join on all servers on available_servers config

    If any of the servers isn't reachable by synapse, it'll return a 500 response, which needs
    to be handled, and if no discovery room is found on any of the available_servers, one in
    our current server should be created
    """
    transport = MatrixTransport({
        'global_rooms': ['discovery'],
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_servers[0],
        'server_name': local_matrix_servers[0].netloc,
        'available_servers': ['http://invalid.server'],
        'private_rooms': private_rooms,
    })
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(
        raiden_service,
        raiden_service.message_handler,
        None,
    )
    transport.log = MagicMock()
    discovery_room_name = make_room_alias(transport.network_id, 'discovery')
    assert isinstance(transport._global_rooms.get(discovery_room_name), Room)

    transport.stop()
    transport.get()


@pytest.mark.parametrize('matrix_server_count', [2])
@pytest.mark.parametrize('number_of_transports', [3])
def test_matrix_cross_server_with_load_balance(matrix_transports, retry_interval):
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

    transport0.start(raiden_service0, message_handler0, '')
    transport1.start(raiden_service1, message_handler1, '')
    transport2.start(raiden_service2, message_handler2, '')

    transport0.start_health_check(raiden_service1.address)
    transport0.start_health_check(raiden_service2.address)

    transport1.start_health_check(raiden_service0.address)
    transport1.start_health_check(raiden_service2.address)

    transport2.start_health_check(raiden_service0.address)
    transport2.start_health_check(raiden_service1.address)

    queueid1 = QueueIdentifier(
        recipient=raiden_service1.address,
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    )
    queueid2 = QueueIdentifier(
        recipient=raiden_service2.address,
        channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    )
    message = Processed(0)
    raiden_service0.sign(message)

    transport0.send_async(queueid1, message)
    transport0.send_async(queueid2, message)

    with Timeout(retry_interval * 10, exception=False):
        all_messages_received = False

        while not all_messages_received:
            all_messages_received = (
                len(received_messages0) == 2 and
                len(received_messages1) == 1 and
                len(received_messages2) == 1
            )
            gevent.sleep(.1)

    assert all_messages_received

    transport0.stop()
    transport1.stop()
    transport2.stop()

    transport0.get()
    transport1.get()
    transport2.get()


def test_matrix_discovery_room_offline_server(
        local_matrix_servers,
        retries_before_backoff,
        retry_interval,
        private_rooms,
):

    transport = MatrixTransport({
        'global_rooms': ['discovery'],
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_servers[0],
        'server_name': local_matrix_servers[0].netloc,
        'available_servers': [local_matrix_servers[0], 'https://localhost:1'],
        'private_rooms': private_rooms,
    })
    transport.start(MockRaidenService(None), MessageHandler(set()), '')
    gevent.sleep(.2)

    discovery_room_name = make_room_alias(transport.network_id, 'discovery')
    assert isinstance(transport._global_rooms.get(discovery_room_name), Room)

    transport.stop()
    transport.get()


def test_matrix_send_global(
        local_matrix_servers,
        retries_before_backoff,
        retry_interval,
        private_rooms,
):
    transport = MatrixTransport({
        'global_rooms': ['discovery', MONITORING_BROADCASTING_ROOM],
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_servers[0],
        'server_name': local_matrix_servers[0].netloc,
        'available_servers': [local_matrix_servers[0]],
        'private_rooms': private_rooms,
    })
    transport.start(MockRaidenService(None), MessageHandler(set()), '')
    gevent.idle()

    ms_room_name = make_room_alias(transport.network_id, MONITORING_BROADCASTING_ROOM)
    ms_room = transport._global_rooms.get(ms_room_name)
    assert isinstance(ms_room, Room)

    ms_room.send_text = MagicMock(spec=ms_room.send_text)

    for i in range(5):
        message = Processed(i)
        transport._raiden_service.sign(message)
        transport.send_global(
            MONITORING_BROADCASTING_ROOM,
            message,
        )

    gevent.idle()

    assert ms_room.send_text.call_count == 5

    transport.stop()
    transport.get()


def test_monitoring_global_messages(
        local_matrix_servers,
        private_rooms,
        retry_interval,
        retries_before_backoff,
):
    """
    Test that RaidenMonitoringEventHandler sends RequestMonitoring messages to global
    MONITORING_BROADCASTING_ROOM room on EventNewBalanceProofReceived.
    """
    transport = MatrixTransport({
        'global_rooms': ['discovery', MONITORING_BROADCASTING_ROOM],
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_servers[0],
        'server_name': local_matrix_servers[0].netloc,
        'available_servers': [local_matrix_servers[0]],
        'private_rooms': private_rooms,
    })
    transport._client.api.retry_timeout = 0
    transport._send_raw = MagicMock()
    raiden_service = MockRaidenService(None)

    transport.start(
        raiden_service,
        raiden_service.message_handler,
        None,
    )

    ms_room_name = make_room_alias(transport.network_id, MONITORING_BROADCASTING_ROOM)
    ms_room = transport._global_rooms.get(ms_room_name)
    assert isinstance(ms_room, Room)
    ms_room.send_text = MagicMock(spec=ms_room.send_text)

    raiden_service.transport = transport
    transport.log = MagicMock()
    new_balance_proof_event = EventNewBalanceProofReceived(
        make_balance_proof(signer=LocalSigner(HOP1_KEY), amount=1),
    )
    RaidenMonitoringEventHandler().on_raiden_event(
        raiden_service,
        new_balance_proof_event,
    )
    gevent.idle()

    assert ms_room.send_text.call_count == 1
    transport.stop()
    transport.get()
