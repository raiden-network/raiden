from collections import defaultdict

import gevent
import pytest
from eth_utils import encode_hex
from gevent import Timeout
from gevent.event import Event
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User

from raiden.constants import Environment, MatrixMessageType
from raiden.messages.transfers import SecretRequest
from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix.client import GMatrixHttpApi
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.network.transport.matrix.transport import RETRY_QUEUE_IDLE_AFTER, _RetryQueue
from raiden.settings import MatrixTransportConfig
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.factories import make_message_identifier, make_signer
from raiden.tests.utils.mocks import MockRaidenService
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.utils.formatting import to_hex_address
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import (
    Address,
    AddressMetadata,
    Any,
    BlockExpiration,
    Optional,
    PaymentAmount,
    PaymentID,
    UserID,
)

USERID0 = UserID("@0x1234567890123456789012345678901234567890:RestaurantAtTheEndOfTheUniverse")
USERID1 = UserID(f"@{to_hex_address(factories.HOP1)}:Wonderland")  # pylint: disable=no-member


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


@pytest.fixture()
def mock_raiden_service():
    return MockRaidenService()


@pytest.fixture()
def mock_matrix(
    monkeypatch,
    mock_raiden_service,
    retry_interval_initial,
    retry_interval_max,
    retries_before_backoff,
):

    from raiden.network.transport.matrix import transport as transport_module
    from raiden.network.transport.matrix.client import GMatrixClient
    from raiden.network.transport.matrix.utils import UserPresence

    def make_client_monkey(
        handle_messages_callback, servers, *args, **kwargs
    ):  # pylint: disable=unused-argument
        return GMatrixClient(
            handle_messages_callback=handle_messages_callback,
            base_url=servers[0],
        )

    monkeypatch.setattr(User, "get_display_name", lambda _: "random_display_name")
    monkeypatch.setattr(transport_module, "make_client", make_client_monkey)

    def mock_on_messages(messages):  # pylint: disable=unused-argument
        for message in messages:
            assert message
            assert message.sender

    def mock_get_user_presence(self, user_id: str):  # pylint: disable=unused-argument
        return UserPresence.ONLINE

    config = MatrixTransportConfig(
        retries_before_backoff=retries_before_backoff,
        retry_interval_initial=retry_interval_initial,
        retry_interval_max=retry_interval_max,
        server="http://none",
        available_servers=[],
    )

    def mock_join_room(self, room_id_or_alias):
        raise MatrixRequestError(
            code=404, content={"errcode": "M_UNKNOWN", "error": "No known servers"}
        )

    transport = MatrixTransport(config=config, environment=Environment.DEVELOPMENT)
    transport._raiden_service = mock_raiden_service
    transport._web_rtc_manager = WebRTCManager(
        mock_raiden_service.address,
        transport._process_raiden_messages,
        transport._send_raw,
        transport._stop_event,
    )
    transport._stop_event.clear()

    transport._client.user_id = USERID0
    transport._started = True

    monkeypatch.setattr(transport._raiden_service, "on_messages", mock_on_messages)
    monkeypatch.setattr(GMatrixClient, "get_user_presence", mock_get_user_presence)
    monkeypatch.setattr(GMatrixClient, "join_room", mock_join_room)

    monkeypatch.setattr(transport._client.api, "leave_room", lambda room_id: None)
    monkeypatch.setattr(transport._client, "sync_token", "already_synced")

    return transport


def create_new_users_for_address(signer=None, number_of_users=1):
    users = []
    if signer is None:
        signer = make_signer()

    for i in range(number_of_users):
        user_id = f"@{signer.address_hex.lower()}:server{i}"
        signature_bytes = signer.sign(user_id.encode())
        signature_hex = encode_hex(signature_bytes)
        user = User(api=None, user_id=user_id, displayname=signature_hex)
        users.append(user)
    return users


@pytest.fixture(scope="session")
def sync_filter_dict():
    return {}


@pytest.fixture
def create_sync_filter_patch(monkeypatch, sync_filter_dict):
    def mock_create_sync_filter(self, user_id, sync_filter):  # pylint: disable=unused-argument
        count = len(sync_filter_dict)
        sync_filter_dict[count] = sync_filter
        return {"filter_id": count}

    monkeypatch.setattr(GMatrixHttpApi, "create_filter", mock_create_sync_filter)


@pytest.fixture
def record_sent_messages(mock_matrix):
    original_send_raw = mock_matrix._send_raw

    sent_messages = []

    def send_raw(
        receiver_address: Address,
        data: str,
        message_type: MatrixMessageType = MatrixMessageType.TEXT,
        receiver_metadata: AddressMetadata = None,
    ) -> None:
        # pylint: disable=unused-argument
        for message in data.split("\n"):
            sent_messages.append((receiver_address, message))

    mock_matrix._send_raw = send_raw
    mock_matrix.sent_messages = sent_messages

    yield

    mock_matrix._send_raw = original_send_raw
    del mock_matrix.sent_messages


def make_message_event(
    recipient: Address,
    address_metadata: Any = None,
    canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
):
    return SendSecretRequest(
        recipient=recipient,
        recipient_metadata=address_metadata,
        canonical_identifier=canonical_identifier,
        message_identifier=make_message_identifier(),
        payment_identifier=PaymentID(1),
        amount=PaymentAmount(1),
        expiration=BlockExpiration(10),
        secrethash=factories.UNIT_SECRETHASH,
    )


def make_message(sign: bool = True, message_event: Optional[SendSecretRequest] = None):
    if message_event is None:
        # recipient etc. doesn't matter, since this will not be considered
        # on converting to a message
        message_event = make_message_event(Address(factories.HOP1))
    message = SecretRequest.from_event(message_event)
    if sign:
        message.sign(LocalSigner(factories.HOP1_KEY))
    return message


def make_message_text(sign=True, overwrite_data=None):
    if not overwrite_data:
        data = MessageSerializer.serialize(make_message(sign=sign))
    else:
        data = overwrite_data

    event = dict(
        type="m.room.message", sender=USERID1, content={"msgtype": "m.text", "body": data}
    )
    return event


def test_normal_processing_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    event = make_message_text()
    assert mock_matrix._handle_messages([event])


def test_processing_invalid_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    invalid_json = '{"foo": 1,'
    event = make_message_text(overwrite_data=invalid_json)
    assert not mock_matrix._handle_messages([event])


def test_non_signed_message_is_rejected(
    mock_matrix, skip_userid_validation
):  # pylint: disable=unused-argument
    event = make_message_text(sign=False)
    assert not mock_matrix._handle_messages([event])


def test_sending_nonstring_body(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    event = make_message_text(overwrite_data=b"somebinarydata")
    assert not mock_matrix._handle_messages([event])


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
    event = make_message_text(overwrite_data=message_input)
    assert not mock_matrix._handle_messages([event])


def test_processing_invalid_message_type_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    invalid_message = '{"_type": "NonExistentMessage", "is": 3, "not_valid": 5}'
    event = make_message_text(overwrite_data=invalid_message)
    assert not mock_matrix._handle_messages([event])


def test_retry_queue_batch_by_user_id(mock_matrix: MatrixTransport) -> None:
    """
    Make sure that the retry-queues batches messages by the attached
    AddressMetadata, and pass the message-data to the _send_raw method per batch.
    """

    original_send_raw = mock_matrix._send_raw
    sent_messages_by_callcount = defaultdict(list)
    sent_messages = []
    send_raw_call_count = 0

    def send_raw(
        receiver_address: Address,
        data: str,
        message_type: MatrixMessageType = MatrixMessageType.TEXT,
        receiver_metadata: AddressMetadata = None,
    ) -> None:
        # pylint: disable=unused-argument
        nonlocal send_raw_call_count
        send_raw_call_count += 1
        for message in data.split("\n"):
            sent_messages.append(message)
            sent_messages_by_callcount[send_raw_call_count].append((message, receiver_metadata))

    mock_matrix._send_raw = send_raw  # type: ignore

    # Pretend the Transport greenlet is running
    mock_matrix.greenlet = True

    receiver_address = Address(factories.HOP1)

    # This is intentionally not using ``MatrixTransport._get_retrier()`` since we don't want the
    # greenlet to run but instead manually call its `_check_and_send()` method.
    retry_queue = _RetryQueue(transport=mock_matrix, receiver=receiver_address)

    # enqueue first message with no address metadata
    address_metadata1 = None
    message_event1 = make_message_event(receiver_address, address_metadata=address_metadata1)
    message1 = make_message(message_event=message_event1)
    serialized_message1 = MessageSerializer.serialize(message1)
    retry_queue.enqueue(message_event1.queue_identifier, [(message1, address_metadata1)])

    # enqueue second message with address metadata dict,
    # but no "user_id" key - this will end up in the same batch as address_metadata=None
    address_metadata2: AddressMetadata = {"no_user_id": UserID("@nothing:here")}

    message_event2 = make_message_event(receiver_address, address_metadata=address_metadata2)
    message2 = make_message(message_event=message_event2)
    serialized_message2 = MessageSerializer.serialize(message2)
    retry_queue.enqueue(message_event2.queue_identifier, [(message2, address_metadata2)])

    # enqueue third message with correct address metadata
    correct_address_metadata: AddressMetadata = {"user_id": USERID1}
    message_event3 = make_message_event(
        receiver_address, address_metadata=correct_address_metadata
    )
    message3 = make_message(message_event=message_event3)
    serialized_message3 = MessageSerializer.serialize(message3)
    retry_queue.enqueue(message_event3.queue_identifier, [(message3, correct_address_metadata)])

    # enqueue another message with correct address metadata
    message_event4 = make_message_event(
        receiver_address, address_metadata=correct_address_metadata
    )
    message4 = make_message(message_event=message_event4)
    serialized_message4 = MessageSerializer.serialize(message4)
    retry_queue.enqueue(message_event4.queue_identifier, [(message4, correct_address_metadata)])

    # enqueue a message with address metadata dict,
    # that has key `user_id`, but is not a "valid" user-id. This should still get passed to the
    # send raw
    address_metadata5: AddressMetadata = {"user_id": UserID("invalid")}
    message_event5 = make_message_event(receiver_address, address_metadata=address_metadata5)
    message5 = make_message(message_event=message_event5)
    serialized_message5 = MessageSerializer.serialize(message5)
    retry_queue.enqueue(message_event5.queue_identifier, [(message5, address_metadata5)])

    # Pretend the Transport greenlet is running
    mock_matrix.greenlet = True

    mock_matrix._queueids_to_queues[message_event1.queue_identifier] = [
        message_event1,
        message_event2,
        message_event3,
        message_event4,
        message_event5,
    ]

    retry_queue._check_and_send()

    assert len(sent_messages) == 5
    # only 3 batches expected by "user_id" in AddressMetadata
    # so transport._send_raw should also only be called 3 times
    assert send_raw_call_count == 3

    # for the first batch, _send_raw will be called with address_metadata=None, because for
    # message2, the address-metadata dict didn't include a "user_id" key
    batch1 = [(serialized_message1, None), (serialized_message2, None)]
    batch2 = [
        (serialized_message3, correct_address_metadata),
        (serialized_message4, correct_address_metadata),
    ]
    batch3 = [(serialized_message5, address_metadata5)]

    for sent_batch in sent_messages_by_callcount.values():
        matches = False
        for batch in [batch1, batch2, batch3]:
            if all(elem in sent_batch for elem in batch):  # type: ignore
                matches = True
                break
        msg = f"Sent batch not expected: {sent_batch}"
        assert matches is True, msg

    mock_matrix._queueids_to_queues[message_event1.queue_identifier].clear()

    mock_matrix._send_raw = original_send_raw  # type: ignore


@pytest.mark.parametrize("retry_interval_initial", [0.01])
@pytest.mark.usefixtures("record_sent_messages")
def test_retry_queue_does_not_resend_removed_messages(
    mock_matrix: MatrixTransport, retry_interval_initial: float
) -> None:
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
    retry_queue = _RetryQueue(transport=mock_matrix, receiver=Address(factories.HOP1))

    message_event = make_message_event(recipient=Address(factories.HOP1))
    message = make_message(message_event=message_event)
    serialized_message = MessageSerializer.serialize(message)

    retry_queue.enqueue(message_event.queue_identifier, [(message, None)])

    mock_matrix._queueids_to_queues[message_event.queue_identifier] = [message_event]

    retry_queue._check_and_send()

    assert len(mock_matrix.sent_messages) == 1  # type: ignore
    assert (factories.HOP1, serialized_message) in mock_matrix.sent_messages  # type: ignore

    mock_matrix._queueids_to_queues[message_event.queue_identifier].clear()

    # Make sure the retry interval has elapsed
    gevent.sleep(retry_interval_initial * 5)

    # The message has been removed from the raiden queue and should therefore not be sent again
    retry_queue._check_and_send()

    assert len(mock_matrix.sent_messages) == 1  # type: ignore


@pytest.mark.parametrize("retry_interval_initial", [0.05])
def test_retryqueue_idle_terminate(mock_matrix: MatrixTransport, retry_interval_initial: float):
    """Ensure ``RetryQueue``s exit if they are idle for too long."""
    retry_queue = mock_matrix._get_retrier(Address(factories.HOP1))
    idle_after = RETRY_QUEUE_IDLE_AFTER * retry_interval_initial

    with Timeout(idle_after + (retry_interval_initial * 5)):
        # Retry
        while not gevent.joinall({retry_queue.greenlet}, idle_after / 2, raise_error=True):
            pass

    assert retry_queue.greenlet.ready()
    assert retry_queue._idle_since == RETRY_QUEUE_IDLE_AFTER
    assert retry_queue.is_idle

    retry_queue_2 = mock_matrix._get_retrier(Address(factories.HOP1))

    # Since the initial RetryQueue has exited `get_retrier()` must return a new instance
    assert retry_queue_2 is not retry_queue


@pytest.mark.parametrize("retry_interval_initial", [0.05])
def test_retryqueue_not_idle_with_messages(
    mock_matrix: MatrixTransport, retry_interval_initial: float
) -> None:
    """Ensure ``RetryQueue``s don't become idle while messages remain in the internal queue."""
    retry_queue = mock_matrix._get_retrier(Address(factories.HOP1))
    idle_after = RETRY_QUEUE_IDLE_AFTER * retry_interval_initial

    queue_identifier = QueueIdentifier(
        recipient=Address(factories.HOP1),
        canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
    )
    retry_queue.enqueue(queue_identifier, [(make_message(), None)])

    # Wait for the idle timeout to expire
    gevent.sleep(idle_after + (retry_interval_initial * 5))

    assert not retry_queue.greenlet.ready()
    assert retry_queue._idle_since == 0
    assert not retry_queue.is_idle

    retry_queue_2 = mock_matrix._get_retrier(Address(factories.HOP1))
    # The first queue has never become idle, therefore the same object must be returned
    assert retry_queue is retry_queue_2


def test_retryqueue_enqueue_not_blocking(mock_matrix: MatrixTransport, monkeypatch) -> None:
    """Ensure ``RetryQueue``s don't become idle while messages remain in the internal queue."""
    # Pretend the Transport greenlet is running
    mock_matrix.greenlet = True

    lock = Event()
    call_count = 0

    def send_raw_blocking(
        receiver_address: Address,
        data: str,
        message_type: MatrixMessageType = MatrixMessageType.TEXT,
        receiver_metadata: AddressMetadata = None,
    ):
        # pylint: disable=unused-argument
        nonlocal call_count
        call_count += 1
        lock.wait()

    monkeypatch.setattr(mock_matrix, "_send_raw", send_raw_blocking)

    retry_queue = mock_matrix._get_retrier(Address(factories.HOP1))

    message_event = make_message_event(recipient=Address(factories.HOP1))
    message = make_message(message_event=message_event)
    mock_matrix._queueids_to_queues[message_event.queue_identifier] = [message_event]
    retry_queue.enqueue(message_event.queue_identifier, [(message, None)])

    gevent.sleep(0.01)

    assert call_count == 1
    assert len(retry_queue._message_queue) == 1

    message_event = make_message_event(recipient=Address(factories.HOP1))
    message = make_message(message_event=message_event)
    # The timeout is to ensure that send_async immediately gives back control to the event loop
    with gevent.Timeout(0, False):
        try:
            mock_matrix._queueids_to_queues[message_event.queue_identifier] = [message_event]
            retry_queue.enqueue(message_event.queue_identifier, [(message, None)])
        except gevent.Timeout:
            raise AssertionError("send_async is blocking")

    # release the lock and switch context
    lock.set()
    gevent.sleep(0.01)

    assert call_count == 2
    assert len(retry_queue._message_queue) == 1
