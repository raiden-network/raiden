import time
from collections import defaultdict
from contextlib import contextmanager

import gevent
import pytest
from gevent import Timeout
from matrix_client.errors import MatrixRequestError

from raiden.constants import DeviceIDs
from raiden.network.transport.matrix.client import GMatrixClient, Room, User
from raiden.network.transport.matrix.utils import (
    UserPresence,
    address_from_userid,
    login,
    make_client,
    make_room_alias,
)

from raiden.tests.utils import factories
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.transport import ignore_messages, new_client
from raiden.utils.signer import Signer
from raiden.utils.typing import Address, Any, Dict, Generator, Tuple

# https://matrix.org/docs/spec/appendices#user-identifiers
USERID_VALID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz-.=_/"


@contextmanager
def must_run_for_at_least(minimum_elapsed_time: float, msg: str) -> Generator:
    start = time.time()
    yield
    elapsed = time.time() - start
    if elapsed < minimum_elapsed_time:
        raise AssertionError(msg)


def create_logged_in_client(server: str) -> Tuple[GMatrixClient, Signer]:
    client = make_client(ignore_messages, [server])
    signer = factories.make_signer()

    login(client, signer, DeviceIDs.RAIDEN)

    return client, signer


def replace_one_letter(s: str) -> str:
    char_at_pos2 = s[2]
    pos_of_char = USERID_VALID_CHARS.index(char_at_pos2)
    pos_of_next_char = pos_of_char + 1 % len(USERID_VALID_CHARS)
    next_char = USERID_VALID_CHARS[pos_of_next_char]

    return s[:2] + next_char + s[2 + 1 :]


def test_assumption_matrix_userid(local_matrix_servers):
    client, _ = create_logged_in_client(local_matrix_servers[0])

    # userid validation expects a str
    none_user_id = None
    with pytest.raises(AttributeError):
        User(client.api, none_user_id)

    # userid validation requires `@`
    empty_user_id = ""
    with pytest.raises(ValueError):
        User(client.api, empty_user_id)

    # userid validation requires `@`
    invalid_user_id = client.user_id[1:]
    with pytest.raises(ValueError):
        User(client.api, invalid_user_id)

    # The format of the userid is valid, however the user does not exist, the
    # server returns an error
    unexisting_user_id = replace_one_letter(client.user_id)
    user = User(client.api, unexisting_user_id)
    with pytest.raises(MatrixRequestError):
        user.get_display_name()

    # The userid is valid and the user exists, this should not raise
    newlogin_client, _ = create_logged_in_client(local_matrix_servers[0])
    user = User(client.api, newlogin_client.user_id)
    user.get_display_name()


class PresenceTracker:
    def __init__(self) -> None:
        self.address_presence: Dict[Address, UserPresence] = defaultdict(
            lambda: UserPresence.UNKNOWN
        )

    def presence_listener(
        self, event: Dict[str, Any], presence_update_id: int  # pylint: disable=unused-argument
    ) -> None:
        address = address_from_userid(event["sender"])

        if address:
            presence = UserPresence(event["content"]["presence"])
            self.address_presence[address] = presence


def test_assumption_user_goes_offline_if_sync_is_not_called_within_35s(local_matrix_servers):
    """A user changes presence status if /sync is not called within 35 seconds.

    Note:

    The timeout value was adjusted to work on the CI, the 5 additional seconds
    are arbitrary.

    Assumption test to make sure the presence information changes as per the following rules:
    - Presence information is UNKNOWN for nodes that don't share a room.
    - A node is considered ONLINE if it has done a /sync call within the past
      timeout.
    - Otherwise the node is OFFLINE.

    If any of the above assumptions changes, then the Matrix transport has to
    be adjusted accordingly.
    """
    # This timeout is used to *avoid* blocking the sync thread, otherwise we
    # would have to generate events for the long-polling to return.
    SHORT_TIMEOUT_MS = 1_000

    # This is the interval in seconds which a client must perform /sync calls
    # to stay online.
    PRESENCE_TIMEOUT = 30
    CI_LATENCY = 5

    tracker1 = PresenceTracker()
    client1, signer1 = create_logged_in_client(local_matrix_servers[0])
    client1.add_presence_listener(tracker1.presence_listener)

    tracker2 = PresenceTracker()
    client2, signer2 = create_logged_in_client(local_matrix_servers[0])
    client2.add_presence_listener(tracker2.presence_listener)

    tracker3 = PresenceTracker()
    client3, signer3 = create_logged_in_client(local_matrix_servers[0])
    client3.add_presence_listener(tracker3.presence_listener)

    client1.blocking_sync(timeout_ms=SHORT_TIMEOUT_MS, latency_ms=SHORT_TIMEOUT_MS)
    client2.blocking_sync(timeout_ms=SHORT_TIMEOUT_MS, latency_ms=SHORT_TIMEOUT_MS)

    msg = (
        "The client called sync but the nodes don't share a room, each node "
        "must only see itself as online."
    )
    assert tracker1.address_presence[signer1.address] == UserPresence.ONLINE, msg
    assert tracker1.address_presence[signer2.address] == UserPresence.UNKNOWN, msg
    assert tracker1.address_presence[signer3.address] == UserPresence.UNKNOWN, msg
    assert tracker2.address_presence[signer1.address] == UserPresence.UNKNOWN, msg
    assert tracker2.address_presence[signer2.address] == UserPresence.ONLINE, msg
    assert tracker2.address_presence[signer3.address] == UserPresence.UNKNOWN, msg

    msg_no_sync = "Client3 never calls sync, all presences must be unknown."
    assert len(tracker3.address_presence) == 0, msg_no_sync

    room: Room = client1.create_room("test", is_public=True)
    client2.join_room(room.canonical_alias)
    client3.join_room(room.canonical_alias)

    client1.blocking_sync(timeout_ms=SHORT_TIMEOUT_MS, latency_ms=SHORT_TIMEOUT_MS)
    client2.blocking_sync(timeout_ms=SHORT_TIMEOUT_MS, latency_ms=SHORT_TIMEOUT_MS)

    msg = "All clients share a room, presence information must be available"
    assert tracker1.address_presence[signer1.address] == UserPresence.ONLINE, msg
    assert tracker1.address_presence[signer2.address] == UserPresence.ONLINE, msg
    assert tracker1.address_presence[signer3.address] == UserPresence.OFFLINE, msg
    assert tracker2.address_presence[signer1.address] == UserPresence.ONLINE, msg
    assert tracker2.address_presence[signer2.address] == UserPresence.ONLINE, msg
    assert tracker2.address_presence[signer3.address] == UserPresence.OFFLINE, msg

    msg_no_sync = "Client3 never calls sync, all presences must be unknown."
    assert len(tracker3.address_presence) == 0, msg_no_sync

    # Wait for PRESENCE_TIMEOUT to happen
    gevent.sleep(PRESENCE_TIMEOUT + CI_LATENCY)

    # Do a new sync, this time client1 must change status to offline
    client2.blocking_sync(timeout_ms=PRESENCE_TIMEOUT, latency_ms=SHORT_TIMEOUT_MS)
    assert tracker2.address_presence[signer1.address] == UserPresence.OFFLINE, msg
    assert tracker2.address_presence[signer2.address] == UserPresence.ONLINE, msg
    assert tracker2.address_presence[signer3.address] == UserPresence.OFFLINE, msg


def test_assumption_user_is_online_while_sync_is_blocking(local_matrix_servers):
    """A user presence does not change while a /sync is blocking.

    This assumption test makes sure a user is considered online while there is
    one outstanding /sync request. This is important because it guides the
    choice of the `DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT` setting. Because the
    node is considered online while the /sync is pending, a large value is
    better to avoid unecessary load to the Matrix server.
    """
    # This is the interval in seconds which a client must perform /sync calls
    # to stay online.
    PRESENCE_TIMEOUT = 30

    # This timeout is used to *avoid* blocking the sync thread, otherwise we
    # would have to generate events for the long-polling to return.
    SHORT_TIMEOUT_MS = 1
    LONG_TIMEOUT_MS = 60_000

    tracker1 = PresenceTracker()
    client1, signer1 = create_logged_in_client(local_matrix_servers[0])
    client1.add_presence_listener(tracker1.presence_listener)

    tracker2 = PresenceTracker()
    client2, _ = create_logged_in_client(local_matrix_servers[0])
    client2.add_presence_listener(tracker2.presence_listener)

    room: Room = client1.create_room("test", is_public=True)
    client2.join_room(room.canonical_alias)

    client2.blocking_sync(timeout_ms=SHORT_TIMEOUT_MS, latency_ms=SHORT_TIMEOUT_MS)
    client1.blocking_sync(timeout_ms=SHORT_TIMEOUT_MS, latency_ms=SHORT_TIMEOUT_MS)

    def long_polling():
        timeout_secs = (LONG_TIMEOUT_MS - 100) / 1_000
        with must_run_for_at_least(timeout_secs, msg):
            client1._sync(timeout_ms=LONG_TIMEOUT_MS, latency_ms=SHORT_TIMEOUT_MS)

        assert len(client1.response_queue) == 1, "Matrix must return *one* valid response"

    msg = "Client1 must not change presence state before LONG_TIMEOUT_MS."
    timeout_secs = (PRESENCE_TIMEOUT - 100) / 1_000
    with must_run_for_at_least(timeout_secs, msg):
        long_running = gevent.spawn(long_polling)

        while long_running:
            gevent.sleep(1)

            client2.blocking_sync(timeout_ms=PRESENCE_TIMEOUT, latency_ms=SHORT_TIMEOUT_MS)
            msg = "Client1 should be online while the sync is blocking"
            assert tracker2.address_presence[signer1.address] == UserPresence.ONLINE, msg

    assert long_running.successful(), "Thread calling sync failed"


@pytest.mark.parametrize("matrix_server_count", [3])
def test_assumption_cannot_override_room_alias(local_matrix_servers):
    """Issue: https://github.com/raiden-network/raiden/issues/5366

    This test creates a room on one matrix server (1) asserting that the room
    has been "federated" to the other servers (2 & 3). In addition, Once the room is
    created, aliases for this room are created on (2 & 3).

    The assumption here is that, once aliases are created, an external user
    will not be able to create a room with a name that already exists as
    an alias, or override existing aliases.
    """
    room_alias_prefix = "public_room"

    server1_client, _ = create_logged_in_client(local_matrix_servers[0])
    server1_client.create_room(room_alias_prefix, is_public=True)

    # Should have the one room we created
    public_room = next(iter(server1_client.rooms.values()))

    for local_server in local_matrix_servers[1:]:
        client = new_client(ignore_messages, local_server)
        assert public_room.room_id not in client.rooms
        client.join_room(public_room.canonical_alias)
        assert public_room.room_id in client.rooms

        alias_on_current_server = f"#{room_alias_prefix}:{local_server.netloc}"
        client.api.set_room_alias(public_room.room_id, alias_on_current_server)

        # Try to create the room again on the current server
        # after it has been aliased.
        with pytest.raises(MatrixRequestError):
            client.create_room(room_alias_prefix, is_public=True)

        # As a different user, try to remove the existing alias
        # and create a new room with that alias.
        client2, _ = create_logged_in_client(local_server)
        with pytest.raises(MatrixRequestError):
            client2.api.remove_room_alias(alias_on_current_server)
            client2.create_room(room_alias_prefix, is_public=True)


@pytest.mark.parametrize("matrix_server_count", [1])
def test_assumption_matrix_returns_same_id_for_same_filter_payload(chain_id, local_matrix_servers):
    """
    Test that for duplicate filter payload, the matrix server would just
    return the existing filter ID rather than creating a new filter and returning
    a new ID. This means that no cleanup for previously created filters
    is required as filtes are re-used.
    """
    client, _ = create_logged_in_client(local_matrix_servers[0])

    room_alias = make_room_alias(chain_id, "broadcast_test")

    broadcast_room = client.create_room(room_alias, is_public=True)

    assert client._sync_filter_id is None

    first_sync_filter_id = client.create_sync_filter(not_rooms=[broadcast_room])

    # Try again and make sure the filter has the same ID
    second_sync_filter_id = client.create_sync_filter(not_rooms=[broadcast_room])
    assert first_sync_filter_id == second_sync_filter_id


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_assumption_broadcast_queue_delays_shutdown(raiden_chain):
    raiden_node = raiden_chain[0]
    # mark broadcast queue dirty
    from gevent.queue import JoinableQueue

    raiden_node.transport._broadcast_queue = JoinableQueue(unfinished_tasks=1)
    # spawn a "stop" and give it some time
    gevent.spawn(raiden_node.stop)
    gevent.sleep(10)
    msg = "Transport stopped before broadcast queue is empty"
    assert not raiden_node.transport._client.stop_event.is_set(), msg
    assert raiden_node.wal is not None, "Node stopped even though transport is not ready"
    # mark broadcast queue clean
    raiden_node.transport._broadcast_queue.task_done()
    assert raiden_node.transport._broadcast_queue.unfinished_tasks == 0
    # now the node stop should succeed
    with Timeout(10):
        while True:
            if raiden_node.wal is None:
                break
            gevent.sleep(1)
    assert raiden_node.wal is None, "Node did not stop"
