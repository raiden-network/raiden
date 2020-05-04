from typing import List, Optional

import gevent
import pytest
from eth_utils import encode_hex
from gevent import Timeout
from matrix_client.errors import MatrixRequestError
from matrix_client.user import User

from raiden.constants import EMPTY_SIGNATURE, Environment
from raiden.messages.abstract import Message
from raiden.messages.transfers import SecretRequest
from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix import AddressReachability
from raiden.network.transport.matrix.client import GMatrixHttpApi, Room
from raiden.network.transport.matrix.transport import RETRY_QUEUE_IDLE_AFTER, _RetryQueue
from raiden.network.transport.matrix.utils import UserAddressManager
from raiden.settings import MatrixTransportConfig
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.factories import make_message_identifier, make_signer
from raiden.tests.utils.mocks import MockRaidenService
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE, QueueIdentifier
from raiden.utils.formatting import to_hex_address
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import Address, BlockExpiration, PaymentAmount, PaymentID, RoomID

USERID0 = "@0x1234567890123456789012345678901234567890:RestaurantAtTheEndOfTheUniverse"
USERID1 = f"@{to_hex_address(factories.HOP1)}:Wonderland"  # pylint: disable=no-member


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

    from raiden.network.transport.matrix.client import GMatrixClient
    from raiden.network.transport.matrix.utils import UserPresence
    from raiden.network.transport.matrix import transport as transport_module

    def make_client_monkey(
        handle_messages_callback, handle_member_join_callback, servers, *args, **kwargs
    ):  # pylint: disable=unused-argument
        return GMatrixClient(
            handle_messages_callback=handle_messages_callback,
            handle_member_join_callback=handle_member_join_callback,
            base_url=servers[0],
        )

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

    def mock_get_user_presence(self, user_id: str):  # pylint: disable=unused-argument
        return UserPresence.ONLINE

    config = MatrixTransportConfig(
        broadcast_rooms=[],
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
    transport._stop_event.clear()
    transport._address_mgr.add_userid_for_address(Address(factories.HOP1), USERID1)
    transport._client.user_id = USERID0

    monkeypatch.setattr(
        MatrixTransport, "_get_room_ids_for_address", mock_get_room_ids_for_address
    )
    monkeypatch.setattr(MatrixTransport, "_set_room_id_for_address", mock_set_room_id_for_address)
    monkeypatch.setattr(transport._raiden_service, "on_messages", mock_on_messages)
    monkeypatch.setattr(GMatrixClient, "get_user_presence", mock_get_user_presence)
    monkeypatch.setattr(GMatrixClient, "join_room", mock_join_room)

    monkeypatch.setattr(transport._client.api, "leave_room", lambda room_id: None)
    monkeypatch.setattr(transport._client, "sync_token", "already_synced")

    return transport


def create_new_users_for_address(signer=None, number_of_users=1):
    users = list()
    if signer is None:
        signer = make_signer()

    for i in range(number_of_users):
        user_id = f"@{signer.address_hex.lower()}:server{i}"
        signature_bytes = signer.sign(user_id.encode())
        signature_hex = encode_hex(signature_bytes)
        user = User(api=None, user_id=user_id, displayname=signature_hex)
        users.append(user)
    return users


@pytest.fixture()
def room_with_members(mock_raiden_service, partner_config_for_room):

    number_of_partners = partner_config_for_room["number_of_partners"]
    users_per_address = partner_config_for_room["users_per_address"]
    number_of_base_users = partner_config_for_room["number_of_base_users"]
    room_members: List[User] = list()
    base_users = create_new_users_for_address(mock_raiden_service.signer, number_of_base_users)
    room_members.extend(base_users)

    for _ in range(number_of_partners):
        users = create_new_users_for_address(number_of_users=users_per_address)
        room_members.extend(users)

    room_id = "!roomofdoom:server"
    room = Room(client=None, room_id=room_id)  # type: ignore
    for member in room_members:
        room._mkmembers(member)

    return room, number_of_partners > 1


@pytest.mark.parametrize(
    "partner_config_for_room",
    [
        pytest.param(
            {"number_of_partners": 1, "users_per_address": 1, "number_of_base_users": 1},
            id="should_not_leave_one_partner",
        ),
        pytest.param(
            {"number_of_partners": 1, "users_per_address": 4, "number_of_base_users": 1},
            id="should_not_leave_multiple_use_one_address",
        ),
        pytest.param(
            {"number_of_partners": 0, "users_per_address": 0, "number_of_base_users": 2},
            id="should_not_leave_no_partner",
        ),
        pytest.param(
            {"number_of_partners": 2, "users_per_address": 1, "number_of_base_users": 1},
            id="should_leave_multiple_partners",
        ),
        pytest.param(
            {"number_of_partners": 3, "users_per_address": 2, "number_of_base_users": 2},
            id="should_leave_multiple_partners_multiple_users",
        ),
    ],
)
@pytest.fixture
def invite_state(signer, mock_matrix):
    invite_user = create_new_users_for_address(signer)[0]

    return {
        "events": [
            {
                "sender": invite_user.user_id,
                "type": "m.room.name",
                "state_key": "",
                "content": {"name": "Invalid Room"},
            },
            {
                "sender": invite_user.user_id,
                "state_key": mock_matrix._user_id,
                "content": {"membership": "invite"},
                "type": "m.room.member",
            },
            {"type": "m.room.join_rules", "content": {"join_rule": "invite"}},
            {
                "content": {
                    "avatar_url": "mxc://example.org/SEsfnsuifSDFSSEF",
                    "displayname": "Alice Margatroid",
                    "membership": "join",
                },
                "event_id": "$143273582443PhrSn:example.org",
                "origin_server_ts": 1432735824653,
                "room_id": "!someroom:invalidserver",
                "sender": invite_user.user_id,
                "state_key": invite_user.user_id,
                "type": "m.room.member",
                "unsigned": {"age": 1234},
            },
        ]
    }


@pytest.mark.parametrize("signer", [make_signer()])
def test_reject_invite_of_invalid_room(
    mock_matrix: MatrixTransport, monkeypatch, signer, invite_state
):

    invalid_room_id = RoomID("!someroom:invalidserver")
    user = create_new_users_for_address(signer)[0]
    mock_matrix._displayname_cache.warm_users([user])

    leave_room_called = False

    def mock_leave_room(room_id):
        nonlocal leave_room_called
        if room_id == invalid_room_id:
            leave_room_called = True

    monkeypatch.setattr(mock_matrix._client.api, "leave_room", mock_leave_room)

    with pytest.raises(AssertionError):
        mock_matrix._handle_invite(invalid_room_id, invite_state)
    assert leave_room_called


@pytest.mark.parametrize(
    "partner_config_for_room",
    [{"number_of_partners": 1, "users_per_address": 1, "number_of_base_users": 1}],
)
def test_leave_after_member_join(mock_matrix, room_with_members):
    # create a valid room with one external member
    room = room_with_members[0]
    user = create_new_users_for_address(make_signer())[0]
    room.client = mock_matrix._client
    mock_matrix._client.rooms[room.room_id] = room

    # response showing that user from another address joins the room
    response_list = list()
    member_join = {
        "room_id": 9,
        "type": "m.room.member",
        "state_key": user.user_id,
        "content": {"membership": "join", "displayname": user.displayname},
    }
    response = {
        "presence": {"events": {}},
        "to_device": {"events": {}},
        "rooms": {
            "invite": {},
            "leave": {},
            "join": {
                room.room_id: {
                    "state": {"events": {}},
                    "ephemeral": {"events": {}},
                    "timeline": {"prev_batch": "PREV_SYNC_TOKEN", "events": [member_join]},
                }
            },
        },
    }
    response_list.append(response)
    mock_matrix._client._handle_responses(response_list)


@pytest.fixture
def all_peers_reachable(monkeypatch):
    def mock_get_address_reachability(
        self, address: Address  # pylint: disable=unused-argument
    ) -> AddressReachability:
        return AddressReachability.REACHABLE

    monkeypatch.setattr(
        UserAddressManager, "get_address_reachability", mock_get_address_reachability
    )


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


@pytest.mark.parametrize(
    "filter_params",
    [
        {
            "not_rooms": [
                Room(None, "!room1:server"),  # type: ignore
                Room(None, "!room2:server"),  # type: ignore
            ],
            "rooms": [
                Room(None, "!room1:server")  # type: ignore
            ],
            "limit": None,
        },
        {"not_rooms": None, "rooms": None, "limit": 0},
        {
            "not_rooms": [
                Room(None, "!room1:server"),  # type: ignore
                Room(None, "!room2:server"),  # type: ignore
            ],
            "rooms": None,
            "limit": 10,
        },
        {"not_rooms": None, "rooms": None, "limit": None},
    ],
)
@pytest.mark.usefixtures("create_sync_filter_patch")
def test_create_sync_filter(mock_matrix, sync_filter_dict, filter_params):
    not_rooms = filter_params["not_rooms"]
    rooms = filter_params["rooms"]
    limit = filter_params["limit"]

    filter_id = mock_matrix._client.create_sync_filter(
        rooms=rooms, not_rooms=not_rooms, limit=limit
    )

    if filter_id is not None:
        sync_filter = sync_filter_dict[filter_id]

    if not_rooms and not limit:
        assert "room" in sync_filter
        assert "presence" in sync_filter
        assert set(sync_filter["room"]["not_rooms"]) == set(room.room_id for room in not_rooms)
        assert set(sync_filter["room"]["rooms"]) == set(room.room_id for room in rooms)
        assert "timeline" not in sync_filter["room"]

    if limit and not not_rooms:
        assert "room" in sync_filter
        assert sync_filter["room"]["timeline"]["limit"] == limit
        assert "presence" not in sync_filter

    if limit and not_rooms:
        assert "timeline" in sync_filter["room"]
        assert "not_rooms" in sync_filter["room"]
        assert "rooms" not in sync_filter["room"]

    if not_rooms is None and rooms is None and limit is None:
        assert filter_id is None


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


def make_message(sign: bool = True) -> Message:
    message = SecretRequest(
        message_identifier=make_message_identifier(),
        payment_identifier=PaymentID(1),
        secrethash=factories.UNIT_SECRETHASH,
        amount=PaymentAmount(1),
        expiration=BlockExpiration(10),
        signature=EMPTY_SIGNATURE,
    )
    if sign:
        message.sign(LocalSigner(factories.HOP1_KEY))
    return message


def make_message_text(sign=True, overwrite_data=None):
    room = Room(None, "!roomID:server")  # type: ignore
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


@pytest.mark.parametrize("retry_interval_initial", [0.01])
@pytest.mark.usefixtures("record_sent_messages", "all_peers_reachable")
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

    message = make_message()
    serialized_message = MessageSerializer.serialize(message)
    queue_identifier = QueueIdentifier(
        recipient=Address(factories.HOP1),
        canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
    )
    retry_queue.enqueue(queue_identifier, [message])

    # TODO: Fix the code below, the types are not matching.
    mock_matrix._queueids_to_queues[queue_identifier] = [message]  # type: ignore

    with retry_queue._lock:
        retry_queue._check_and_send()

    assert len(mock_matrix.sent_messages) == 1  # type: ignore
    assert (factories.HOP1, serialized_message) in mock_matrix.sent_messages  # type: ignore

    mock_matrix._queueids_to_queues[queue_identifier].clear()

    # Make sure the retry interval has elapsed
    gevent.sleep(retry_interval_initial * 5)

    with retry_queue._lock:
        # The message has been removed from the raiden queue and should therefore not be sent again
        retry_queue._check_and_send()

    assert len(mock_matrix.sent_messages) == 1  # type: ignore


@pytest.mark.parametrize("retry_interval_initial", [0.05])
def test_retryqueue_idle_terminate(mock_matrix: MatrixTransport, retry_interval_initial: float):
    """ Ensure ``RetryQueue``s exit if they are idle for too long. """
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
    """ Ensure ``RetryQueue``s don't become idle while messages remain in the internal queue. """
    retry_queue = mock_matrix._get_retrier(Address(factories.HOP1))
    idle_after = RETRY_QUEUE_IDLE_AFTER * retry_interval_initial

    queue_identifier = QueueIdentifier(
        recipient=Address(factories.HOP1),
        canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
    )
    retry_queue.enqueue(queue_identifier, [make_message()])

    # Without the `all_peers_reachable` fixture, the default reachability will be `UNREACHABLE`
    # therefore the message will remain in the internal queue indefinitely.

    # Wait for the idle timeout to expire
    gevent.sleep(idle_after + (retry_interval_initial * 5))

    assert not retry_queue.greenlet.ready()
    assert retry_queue._idle_since == 0
    assert not retry_queue.is_idle

    retry_queue_2 = mock_matrix._get_retrier(Address(factories.HOP1))
    # The first queue has never become idle, therefore the same object must be returned
    assert retry_queue is retry_queue_2
