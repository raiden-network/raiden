import json
import random
from unittest.mock import MagicMock

import gevent
import pytest

from raiden.constants import UINT64_MAX
from raiden.messages import Processed, SecretRequest
from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix import UserPresence, _RetryQueue
from raiden.tests.utils.factories import HOP1, HOP1_KEY, UNIT_SECRETHASH, make_address
from raiden.tests.utils.transport import MockRaidenService
from raiden.transfer.mediated_transfer.events import CHANNEL_IDENTIFIER_GLOBAL_QUEUE
from raiden.transfer.queue_identifier import QueueIdentifier
from raiden.transfer.state_change import ActionUpdateTransportSyncToken
from raiden.utils import pex
from raiden.utils.typing import Address, List, Optional, Union

USERID1 = '@Alice:Wonderland'


@pytest.fixture
def mock_matrix(
        monkeypatch,
        retry_interval,
        retries_before_backoff,
        local_matrix_server,
        private_rooms,
):

    from matrix_client.user import User
    monkeypatch.setattr(User, 'get_display_name', lambda _: 'random_display_name')

    def mock_get_user(klass, user: Union[User, str]) -> User:
        return User(None, USERID1)

    def mock_get_room_ids_for_address(
            klass,
            address: Address,
            filter_private: bool=None,
    ) -> List[str]:
        return ['!roomID:server']

    def mock_set_room_id_for_address(self, address: Address, room_id: Optional[str]):
        pass

    def mock_receive_message(klass, message):
        # We are just unit testing the matrix transport receive so do nothing
        assert message

    def mock_receive_delivered(klass, delivered):
        # We are just unit testing the matrix transport receive so do nothing
        assert delivered

    config = dict(
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        server=local_matrix_server,
        server_name='matrix.local.raiden',
        available_servers=[],
        discovery_room='discovery',
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
    def mock_validate_userid_signature(klass, user):
        return HOP1

    monkeypatch.setattr(
        MatrixTransport,
        '_validate_userid_signature',
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
        message.sign(HOP1_KEY)
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


def test_normal_processing_hex(mock_matrix, skip_userid_validation, skip_if_not_matrix):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    assert m._handle_message(room, event)


def test_normal_processing_json(mock_matrix, skip_userid_validation, skip_if_not_matrix):
    m = mock_matrix
    room, event = make_message(convert_to_hex=False)
    assert m._handle_message(room, event)


def test_processing_invalid_json(mock_matrix, skip_userid_validation, skip_if_not_matrix):
    m = mock_matrix
    invalid_json = '{"foo": 1,'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_json)
    assert not m._handle_message(room, event)


def test_sending_nonstring_body(mock_matrix, skip_userid_validation, skip_if_not_matrix):
    m = mock_matrix
    room, event = make_message(overwrite_data=b'somebinarydata')
    assert not m._handle_message(room, event)


def test_processing_invalid_message_json(
        mock_matrix,
        skip_userid_validation,
        skip_if_not_matrix,
):
    m = mock_matrix
    invalid_message = '{"this": 1, "message": 5, "is": 3, "not_valid": 5}'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_message)
    assert not m._handle_message(room, event)


def test_processing_invalid_message_cmdid_json(
        mock_matrix,
        skip_userid_validation,
        skip_if_not_matrix,
):
    m = mock_matrix
    invalid_message = '{"type": "NonExistentMessage", "is": 3, "not_valid": 5}'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_message)
    assert not m._handle_message(room, event)


def test_processing_invalid_hex(mock_matrix, skip_userid_validation, skip_if_not_matrix):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = old_data[:-1]
    assert not m._handle_message(room, event)


def test_processing_invalid_message_hex(mock_matrix, skip_userid_validation, skip_if_not_matrix):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = old_data[:-4]
    assert not m._handle_message(room, event)


def test_processing_invalid_message_cmdid_hex(
        mock_matrix,
        skip_userid_validation,
        skip_if_not_matrix,
):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = '0xff' + old_data[4:]
    assert not m._handle_message(room, event)


def test_matrix_message_sync(
        skip_if_not_matrix,
        local_matrix_server,
        private_rooms,
        retry_interval,
        retries_before_backoff,
):
    transport0 = MatrixTransport({
        'discovery_room': 'discovery',
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_server,
        'server_name': 'matrix.local.raiden',
        'available_servers': [],
        'private_rooms': private_rooms,
    })
    transport1 = MatrixTransport({
        'discovery_room': 'discovery',
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_server,
        'server_name': 'matrix.local.raiden',
        'available_servers': [],
        'private_rooms': private_rooms,
    })

    latest_sync_token = None

    received_messages = set()

    def hook(sync_token):
        nonlocal latest_sync_token
        latest_sync_token = sync_token

    class MessageHandler:
        def on_message(self, _, message):
            nonlocal received_messages
            received_messages.add(message)

    transport0._client.set_post_sync_hook(hook)
    message_handler = MessageHandler()
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

    transport0.start_health_check(transport1._raiden_service.address)
    transport1.start_health_check(transport0._raiden_service.address)

    queue_identifier = QueueIdentifier(
        recipient=transport1._raiden_service.address,
        channel_identifier=1,
    )

    for i in range(5):
        message = Processed(i)
        message.sign(transport0._raiden_service.private_key)
        transport0.send_async(
            queue_identifier,
            message,
        )

    gevent.sleep(2)

    latest_sync_token = f'{transport1._user_id}/{latest_sync_token}'
    update_transport_sync_token = ActionUpdateTransportSyncToken(latest_sync_token)
    raiden_service1.handle_state_change.assert_called_with(update_transport_sync_token)

    assert len(received_messages) == 10
    for i in range(5):
        assert any(getattr(m, 'message_identifier', -1) == i for m in received_messages)

    transport1.stop()

    assert latest_sync_token

    # Send more messages while the other end is offline
    for i in range(10, 15):
        message = Processed(i)
        message.sign(transport0._raiden_service.private_key)
        transport0.send_async(
            queue_identifier,
            message,
        )

    # Should fetch the 5 messages sent while transport1 was offline
    transport1.start(
        transport1._raiden_service,
        message_handler,
        latest_sync_token,
    )

    gevent.sleep(2)

    assert len(set(received_messages)) == 20
    for i in range(10, 15):
        assert any(getattr(m, 'message_identifier', -1) == i for m in received_messages)

    transport0.stop()
    transport1.stop()


def test_matrix_message_retry(
    skip_if_not_matrix,
    local_matrix_server,
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
        'discovery_room': 'discovery',
        'retries_before_backoff': retries_before_backoff,
        'retry_interval': retry_interval,
        'server': local_matrix_server,
        'server_name': 'matrix.local.raiden',
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

    retry_queue = _RetryQueue(transport, partner_address)
    retry_queue.start()

    # Send the initial message
    message = Processed(0)
    message.sign(transport._raiden_service.private_key)
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
