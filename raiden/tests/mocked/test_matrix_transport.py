import random
from typing import List, Optional

import gevent
import pytest
from gevent import Timeout

from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX, Environment
from raiden.messages.transfers import SecretRequest
from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix import AddressReachability
from raiden.network.transport.matrix.client import Room
from raiden.network.transport.matrix.transport import RETRY_QUEUE_IDLE_AFTER, _RetryQueue
from raiden.network.transport.matrix.utils import UserAddressManager
from raiden.settings import MatrixTransportConfig
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.mocks import MockRaidenService
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.utils.formatting import to_checksum_address
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import Address

USERID0 = "@0x1234567890123456789012345678901234567890:RestaurantAtTheEndOfTheUniverse"
USERID1 = f"@{to_checksum_address(factories.HOP1.hex())}:Wonderland"


@pytest.fixture()
def skip_userid_validation(monkeypatch):
    import raiden.network.transport.matrix
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


@pytest.fixture
def mock_matrix(monkeypatch, retry_interval, retries_before_backoff):

    from raiden.network.transport.matrix.client import GMatrixClient, User
    from raiden.network.transport.matrix.utils import UserPresence
    from raiden.network.transport.matrix import transport as transport_module

    def make_client_monkey(handle_messages_callback, servers, *args, **kwargs):
        return GMatrixClient(handle_messages_callback, servers[0])

    monkeypatch.setattr(User, "get_display_name", lambda _: "random_display_name")
    monkeypatch.setattr(transport_module, "make_client", make_client_monkey)

    def mock_get_room_ids_for_address(  # pylint: disable=unused-argument
        klass, address: Address
    ) -> List[str]:
        return ["!roomID:server"]

    def mock_set_room_id_for_address(  # pylint: disable=unused-argument
        self, address: Address, room_id: Optional[str]
    ):
        pass

    def mock_on_messages(messages):  # pylint: disable=unused-argument
        for message in messages:
            assert message
            assert message.sender

    def mock_get_user_presence(self, user_id: str):
        return UserPresence.ONLINE

    config = MatrixTransportConfig(
        broadcast_rooms=[],
        retries_before_backoff=retries_before_backoff,
        retry_interval=retry_interval,
        server="http://none",
        server_name="none",
        available_servers=[],
    )

    transport = MatrixTransport(config=config, environment=Environment.DEVELOPMENT)
    transport._raiden_service = MockRaidenService()
    transport._stop_event.clear()
    transport._address_mgr.add_userid_for_address(factories.HOP1, USERID1)
    transport._client.user_id = USERID0

    monkeypatch.setattr(
        MatrixTransport, "_get_room_ids_for_address", mock_get_room_ids_for_address
    )
    monkeypatch.setattr(MatrixTransport, "_set_room_id_for_address", mock_set_room_id_for_address)
    monkeypatch.setattr(transport._raiden_service, "on_messages", mock_on_messages)
    monkeypatch.setattr(GMatrixClient, "get_user_presence", mock_get_user_presence)

    return transport


@pytest.fixture
def all_peers_reachable(monkeypatch):
    def mock_get_address_reachability(self, address: Address) -> AddressReachability:
        return AddressReachability.REACHABLE

    monkeypatch.setattr(
        UserAddressManager, "get_address_reachability", mock_get_address_reachability
    )


@pytest.fixture
def record_sent_messages(mock_matrix):
    original_send_raw = mock_matrix._send_raw

    sent_messages = list()

    def send_raw(receiver_address: Address, data: str) -> None:
        for message in data.split("\n"):
            sent_messages.append((receiver_address, message))

    mock_matrix._send_raw = send_raw
    mock_matrix.sent_messages = sent_messages

    yield

    mock_matrix._send_raw = original_send_raw
    del mock_matrix.sent_messages


def make_message(sign=True):
    message = SecretRequest(
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        secrethash=factories.UNIT_SECRETHASH,
        amount=1,
        expiration=10,
        signature=EMPTY_SIGNATURE,
    )
    if sign:
        message.sign(LocalSigner(factories.HOP1_KEY))
    return message


def make_message_text(sign=True, overwrite_data=None):
    room = Room(None, "!roomID:server")
    if not overwrite_data:
        data = MessageSerializer.serialize(make_message(sign=sign))
    else:
        data = overwrite_data

    event = dict(
        type="m.room.message", sender=USERID1, content={"msgtype": "m.text", "body": data}
    )
    return room, event


def test_normal_processing_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    room, event = make_message_text()
    assert mock_matrix._handle_sync_messages([(room, [event])])


def test_processing_invalid_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    invalid_json = '{"foo": 1,'
    room, event = make_message_text(overwrite_data=invalid_json)
    assert not mock_matrix._handle_sync_messages([(room, [event])])


def test_non_signed_message_is_rejected(
    mock_matrix, skip_userid_validation
):  # pylint: disable=unused-argument
    room, event = make_message_text(sign=False)
    assert not mock_matrix._handle_sync_messages([(room, [event])])


def test_sending_nonstring_body(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    room, event = make_message_text(overwrite_data=b"somebinarydata")
    assert not mock_matrix._handle_sync_messages([(room, [event])])


@pytest.mark.parametrize(
    "message_input",
    [
        pytest.param('{"this": 1, "message": 5, "is": 3, "not_valid": 5}', id="json-1"),
        pytest.param("[", id="json-2"),
    ],
)
def test_processing_invalid_message_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation, message_input
):
    room, event = make_message_text(overwrite_data=message_input)
    assert not mock_matrix._handle_sync_messages([(room, [event])])


def test_processing_invalid_message_type_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    invalid_message = '{"_type": "NonExistentMessage", "is": 3, "not_valid": 5}'
    room, event = make_message_text(overwrite_data=invalid_message)
    assert not mock_matrix._handle_sync_messages([(room, [event])])


@pytest.mark.parametrize("retry_interval", [0.01])
def test_retry_queue_does_not_resend_removed_messages(
    mock_matrix, record_sent_messages, retry_interval, all_peers_reachable
):
    """
    Ensure the ``RetryQueue`` doesn't unnecessarily re-send messages.

    Messages should only be retried while they are present in the respective Raiden queue.
    Once they have been removed they should not be sent again.

    In the past they could have been sent twice.
    See: https://github.com/raiden-network/raiden/issue/4111
    """
    # Pretend the Transport greenlet is running
    mock_matrix.greenlet = True

    # This is intentionally not using ``MatrixTransport._get_retrier()`` since we don't want the
    # greenlet to run but instead manually call its `_check_and_send()` method.
    retry_queue = _RetryQueue(transport=mock_matrix, receiver=factories.HOP1)

    message = make_message()
    serialized_message = MessageSerializer.serialize(message)
    queue_identifier = QueueIdentifier(
        recipient=factories.HOP1, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
    )
    retry_queue.enqueue(queue_identifier, message)

    mock_matrix._queueids_to_queues[queue_identifier] = [message]

    with retry_queue._lock:
        retry_queue._check_and_send()

    assert len(mock_matrix.sent_messages) == 1
    assert (factories.HOP1, serialized_message) in mock_matrix.sent_messages

    mock_matrix._queueids_to_queues[queue_identifier].clear()

    # Make sure the retry interval has elapsed
    gevent.sleep(retry_interval * 5)

    with retry_queue._lock:
        # The message has been removed from the raiden queue and should therefore not be sent again
        retry_queue._check_and_send()

    assert len(mock_matrix.sent_messages) == 1


@pytest.mark.parametrize("retry_interval", [0.05])
def test_retryqueue_idle_terminate(mock_matrix: MatrixTransport, retry_interval: int):
    """ Ensure ``RetryQueue``s exit if they are idle for too long. """
    retry_queue = mock_matrix._get_retrier(factories.HOP1)
    idle_after = RETRY_QUEUE_IDLE_AFTER * retry_interval

    with Timeout(idle_after + (retry_interval * 5)):
        # Retry
        while not gevent.wait([retry_queue.greenlet], idle_after / 2):
            pass

    assert retry_queue.greenlet.ready()
    assert retry_queue._idle_since == RETRY_QUEUE_IDLE_AFTER
    assert retry_queue.is_idle

    retry_queue_2 = mock_matrix._get_retrier(factories.HOP1)

    # Since the initial RetryQueue has exited `get_retrier()` must return a new instance
    assert retry_queue_2 is not retry_queue


@pytest.mark.parametrize("retry_interval", [0.05])
def test_retryqueue_not_idle_with_messages(mock_matrix: MatrixTransport, retry_interval: int):
    """ Ensure ``RetryQueue``s don't become idle while messages remain in the internal queue. """
    retry_queue = mock_matrix._get_retrier(factories.HOP1)
    idle_after = RETRY_QUEUE_IDLE_AFTER * retry_interval

    queue_identifier = QueueIdentifier(
        recipient=factories.HOP1, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
    )
    retry_queue.enqueue(queue_identifier, make_message())

    # Without the `all_peers_reachable` fixture, the default reachability will be `UNREACHABLE`
    # therefore the message will remain in the internal queue indefinitely.

    # Wait for the idle timeout to expire
    gevent.sleep(idle_after + (retry_interval * 5))

    assert not retry_queue.greenlet.ready()
    assert retry_queue._idle_since == 0
    assert not retry_queue.is_idle

    retry_queue_2 = mock_matrix._get_retrier(factories.HOP1)
    # The first queue has never become idle, therefore the same object must be returned
    assert retry_queue is retry_queue_2
