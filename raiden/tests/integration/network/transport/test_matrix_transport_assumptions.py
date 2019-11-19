from urllib.parse import urlsplit

import pytest
from eth_utils import to_checksum_address
from matrix_client.errors import MatrixRequestError

from raiden.network.transport.matrix.client import GMatrixClient, User
from raiden.network.transport.matrix.utils import (
    join_broadcast_room,
    login,
    make_client,
    make_room_alias,
)
from raiden.tests.utils import factories
from raiden.utils.signer import Signer
from raiden.utils.typing import Tuple

# https://matrix.org/docs/spec/appendices#user-identifiers
USERID_VALID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz-.=_/"


def create_logged_in_client(server: str) -> Tuple[GMatrixClient, Signer]:
    client = make_client([server])
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
    new_client, _ = create_logged_in_client(local_matrix_servers[0])
    user = User(client.api, new_client.user_id)
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
