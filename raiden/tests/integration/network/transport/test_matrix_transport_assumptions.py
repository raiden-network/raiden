import time
from collections import defaultdict
from contextlib import contextmanager
from functools import partial
from urllib.parse import urlsplit

import gevent
import pytest
from matrix_client.errors import MatrixRequestError

from raiden.network.transport.matrix.client import GMatrixClient, Room, User
from raiden.network.transport.matrix.transport import MatrixTransport
from raiden.network.transport.matrix.utils import (
    UserPresence,
    address_from_userid,
    join_broadcast_room,
    login,
    make_client,
    make_room_alias,
)
from raiden.settings import (
    DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY,
    DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
)
from raiden.tests.utils import factories
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.tests.utils.mocks import MockRaidenService
from raiden.tests.utils.transport import (
    get_admin_credentials,
    ignore_member_join,
    ignore_messages,
    new_client,
)
from raiden.utils.formatting import to_hex_address
from raiden.utils.http import HTTPExecutor
from raiden.utils.signer import Signer
from raiden.utils.typing import Address, Any, Dict, Generator, List, Tuple

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
    client = make_client(ignore_messages, ignore_member_join, [server])
    signer = factories.make_signer()

    login(client, signer)

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
    client2.join_room(room.aliases[0])
    client3.join_room(room.aliases[0])

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
    client2.join_room(room.aliases[0])

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


@pytest.mark.parametrize("matrix_server_count", [2])
def test_assumption_search_user_directory_returns_federated_users(chain_id, local_matrix_servers):
    """The search_user_directory should return federated users.

    This assumption test was added because of issue #5285. The
    path-finding-service was not functioning properly because the call to
    `search_user_directory` did not return federated users, only local users.
    Becaused of that the PFS assumed the users were offline and didn't find any
    valid routes for the payments.
    """
    original_server_url = urlsplit(local_matrix_servers[0]).netloc

    room_alias = make_room_alias(chain_id, "broadcast_test")
    room_name_full = f"#{room_alias}:{original_server_url}"

    user_room_creator, _ = create_logged_in_client(local_matrix_servers[0])
    user_room_creator.create_room(room_alias, is_public=True)

    user_federated, _ = create_logged_in_client(local_matrix_servers[1])
    join_broadcast_room(user_federated, room_name_full)

    addresses = list()
    for _ in range(1000):
        user, signer = create_logged_in_client(local_matrix_servers[0])
        join_broadcast_room(user, room_name_full)

        # Make sure to close the session instance, otherwise there will be too
        # many file descriptors opened by the underlying urllib3 connection
        # pool.
        user.api.session.close()
        del user

        addresses.append(signer.address)

    for address in addresses:
        assert user_federated.search_user_directory(to_hex_address(address))


@pytest.mark.parametrize("matrix_server_count", [3])
def test_assumption_cannot_override_room_alias(local_matrix_servers):
    """ Issue: https://github.com/raiden-network/raiden/issues/5366

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
        client = new_client(ignore_messages, ignore_member_join, local_server)
        assert public_room.room_id not in client.rooms
        client.join_room(public_room.aliases[0])
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


@pytest.mark.parametrize("matrix_server_count", [3])
def test_assumption_federation_works_after_original_server_goes_down(
    chain_id, local_matrix_servers_with_executor
):
    """ Check that a federated broadcast room keeps working after the original server goes down.

    This creates a federation of three matrix servers and a client for each.
    It then checks that all nodes receive messages from the broadcast room.
    Then the first matrix server is shut down and a second message send to
    the broadcast room, which should arrive at both remaining clients.
    """
    original_server_url = urlsplit(local_matrix_servers_with_executor[0][0]).netloc

    room_alias = make_room_alias(chain_id, "broadcast_test")
    room_name_full = f"#{room_alias}:{original_server_url}"

    user_room_creator, _ = create_logged_in_client(local_matrix_servers_with_executor[0][0])
    original_room: Room = user_room_creator.create_room(room_alias, is_public=True)
    user_room_creator.start_listener_thread(
        timeout_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
        latency_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY,
    )

    user_federated_1, _ = create_logged_in_client(local_matrix_servers_with_executor[1][0])
    room_server1 = join_broadcast_room(user_federated_1, room_name_full)
    user_federated_1.rooms[room_server1.room_id] = room_server1
    user_federated_1.start_listener_thread(
        timeout_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
        latency_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY,
    )

    user_federated_2, _ = create_logged_in_client(local_matrix_servers_with_executor[2][0])
    room_server2 = join_broadcast_room(user_federated_2, room_name_full)
    user_federated_2.rooms[room_server2.room_id] = room_server2
    user_federated_2.start_listener_thread(
        timeout_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
        latency_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY,
    )

    received = {}

    def handle_message(node_id: int, _room: Room, event: Dict[str, Any]):
        nonlocal received
        received[node_id] = event["content"]["body"]

    original_room.add_listener(partial(handle_message, 0), "m.room.message")
    room_server1.add_listener(partial(handle_message, 1), "m.room.message")
    room_server2.add_listener(partial(handle_message, 2), "m.room.message")

    # Full federation, send a message to check it works
    original_room.send_text("Message1")

    while not len(received) == 3:
        gevent.sleep(0.1)

    assert sorted(received.keys()) == [0, 1, 2]
    assert all("Message1" == m for m in received.values())

    # Shut down the room_creator before we stop the server
    user_room_creator.stop_listener_thread()
    # Shutdown server 0, the original creator of the room
    server: HTTPExecutor = local_matrix_servers_with_executor[0][1]
    server.stop()

    # Send message from client 1, check that client 2 receives it
    received = {}
    room_server1.send_text("Message2")

    while not len(received) == 2:
        gevent.sleep(0.1)

    assert sorted(received.keys()) == [1, 2]
    assert all("Message2" == m for m in received.values())

    # Shut down longrunning threads
    user_federated_1.stop_listener_thread()
    user_federated_2.stop_listener_thread()

    # TODO: restart matrix server 1, check that message 2 arrives


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


@pytest.mark.parametrize("number_of_transports", [3])
@pytest.mark.parametrize("matrix_server_count", [1])
def test_admin_is_allowed_to_kick(matrix_transports, local_matrix_servers):
    server_name = local_matrix_servers[0].netloc
    admin_credentials = get_admin_credentials(server_name)
    broadcast_room_name = make_room_alias(UNIT_CHAIN_ID, "discovery")
    broadcast_room_alias = f"#{broadcast_room_name}:{server_name}"

    transport0, transport1, transport2 = matrix_transports

    raiden_service0 = MockRaidenService()
    raiden_service1 = MockRaidenService()
    # start transports to join broadcast rooms as normal users
    transport0.start(raiden_service0, [], None)
    transport1.start(raiden_service1, [], None)
    # admin login using raiden.tests.utils.transport.AdminAuthProvider
    admin_client = GMatrixClient(ignore_messages, ignore_member_join, local_matrix_servers[0])
    admin_client.login(admin_credentials["username"], admin_credentials["password"], sync=False)
    room_id = admin_client.join_room(broadcast_room_alias).room_id

    # get members of room and filter not kickable users (power level 100)
    def _get_joined_room_members():
        membership_events = admin_client.api.get_room_members(room_id)["chunk"]
        member_ids = [
            event["state_key"]
            for event in membership_events
            if event["content"]["membership"] == "join"
        ]
        return set(member_ids)

    members = _get_joined_room_members()
    power_levels_event = admin_client.api.get_power_levels(room_id)
    admin_user_ids = [key for key, value in power_levels_event["users"].items() if value >= 50]
    non_admin_user_ids = [member for member in members if member not in admin_user_ids]
    # transport0 and transport1 should still be in non_admin_user_ids
    assert len(non_admin_user_ids) > 1
    kick_user_id = non_admin_user_ids[0]

    # kick one user
    admin_client.api.kick_user(room_id, kick_user_id)

    # Assert missing member
    members_after_kick = _get_joined_room_members()
    assert len(members_after_kick) == len(members) - 1
    members_after_kick.add(kick_user_id)
    assert members_after_kick == members

    # check assumption that new user does not receive presence
    raiden_service2 = MockRaidenService()

    def local_presence_listener(event, event_id):  # pylint: disable=unused-argument
        assert event["sender"] != kick_user_id

    transport2._client.add_presence_listener(local_presence_listener)
    transport2.start(raiden_service2, [], None)

    transport2.stop()

    # rejoin and assert that normal user cannot kick
    kicked_transport = transport0 if transport0._user_id == kick_user_id else transport1
    kicked_transport._client.join_room(broadcast_room_alias)

    with pytest.raises(MatrixRequestError):
        kicked_transport._client.api.kick_user(room_id, non_admin_user_ids[1])


@pytest.mark.parametrize("number_of_transports", [20])
@pytest.mark.parametrize("matrix_server_count", [1])
def test_assumption_receive_all_state_events_upon_first_sync_after_join(
    matrix_transports, number_of_transports, monkeypatch
):
    """
    Test that independently of the number of timeline events in the room
    the first sync after the join always contains all room state events
    more explicitly all member joins. This means the user always knows
    all members of a room at the first sync after the joining the room.
    (Some state events are placed in the timeline history. That does not
    change the logic but it must be given that no state events are filtered
    due to limitation of the timeline limit filter)
    """
    transports: List[MatrixTransport] = list()
    # it is necessary to monkeypatch leave_unexpected_rooms
    # otherwise rooms would be left automatically when members > 2
    monkeypatch.setattr(
        MatrixTransport, "_leave_unexpected_rooms", lambda self, rooms_to_leave, reason: None
    )

    # start all transports
    for transport in matrix_transports:
        raiden_service = MockRaidenService()
        transport.start(raiden_service, [], None)
        transports.append(transport)

    transport0 = transports[0]
    transport1 = transports[1]
    room0 = transport0._client.create_room()

    # invite every user but transport[1]
    for transport in transports[2:]:
        room0.invite_user(transport._user_id)
        transport0._client.synced.wait()

    # wait for every user to be joined
    while len(room0.get_joined_members()) < number_of_transports - 1:
        transport0._client.synced.wait()

    # start filling timeline events by sending messages
    for i in range(1, 100):
        room0.send_text(f"ping{i}")
        gevent.sleep(0.05)

    # finally invite transport[1]
    room0.invite_user(transport1._user_id)

    # wait for the first sync after join
    while room0.room_id not in transport1._client.rooms:
        transport1._client.synced.wait()
    transport1._client.synced.wait()

    # check that all information about existing members are received
    assert (
        len(transport1._client.rooms[room0.room_id].get_joined_members()) == number_of_transports
    )
