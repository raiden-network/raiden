from functools import partial
from urllib.parse import urlsplit

import gevent
import pytest
from matrix_client.errors import MatrixRequestError

from raiden.network.transport.matrix.client import GMatrixClient, Room, User
from raiden.network.transport.matrix.utils import (
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
from raiden.tests.utils.transport import ignore_messages, new_client
from raiden.utils.formatting import to_checksum_address
from raiden.utils.http import HTTPExecutor
from raiden.utils.signer import Signer
from raiden.utils.typing import Any, Dict, Tuple

# https://matrix.org/docs/spec/appendices#user-identifiers
USERID_VALID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz-.=_/"


def create_logged_in_client(server: str) -> Tuple[GMatrixClient, Signer]:
    client = make_client(ignore_messages, [server])
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
        assert user_federated.search_user_directory(to_checksum_address(address))


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
    public_room = next(iter(server1_client.get_rooms().values()))

    for local_server in local_matrix_servers[1:]:
        client = new_client(ignore_messages, local_server)
        assert public_room.room_id not in client.get_rooms()
        client.join_room(public_room.aliases[0])
        assert public_room.room_id in client.get_rooms()

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
    user_federated_1.start_listener_thread(
        timeout_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_TIMEOUT,
        latency_ms=DEFAULT_TRANSPORT_MATRIX_SYNC_LATENCY,
    )

    user_federated_2, _ = create_logged_in_client(local_matrix_servers_with_executor[2][0])
    room_server2 = join_broadcast_room(user_federated_2, room_name_full)
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

    first_sync_filter_id = client.create_sync_filter(
        broadcast_rooms={broadcast_room.name: broadcast_room}
    )

    # Try again and make sure the filter has the same ID
    second_sync_filter_id = client.create_sync_filter(
        broadcast_rooms={broadcast_room.name: broadcast_room}
    )
    assert first_sync_filter_id == second_sync_filter_id
