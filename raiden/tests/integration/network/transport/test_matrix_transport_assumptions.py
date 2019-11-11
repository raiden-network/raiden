from urllib.parse import urlsplit

import pytest
from eth_utils import encode_hex, to_normalized_address
from matrix_client.errors import MatrixRequestError

from raiden.network.transport.matrix.client import GMatrixClient, User
from raiden.network.transport.matrix.utils import make_client
from raiden.tests.utils import factories
from raiden.utils.signer import LocalSigner

# https://matrix.org/docs/spec/appendices#user-identifiers
USERID_VALID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz-.=_/"


def create_logged_in_client(server: str) -> GMatrixClient:
    privkey, _ = factories.make_privkey_address()
    signer = LocalSigner(privkey)
    client = make_client([server])
    server_name = urlsplit(server).netloc

    username = str(to_normalized_address(signer.address))
    password = encode_hex(signer.sign(server_name.encode()))
    client.login(username, password, sync=False)

    return client


def replace_one_letter(s: str) -> str:
    char_at_pos2 = s[2]
    pos_of_char = USERID_VALID_CHARS.index(char_at_pos2)
    pos_of_next_char = pos_of_char + 1 % len(USERID_VALID_CHARS)
    next_char = USERID_VALID_CHARS[pos_of_next_char]

    return s[:2] + next_char + s[2 + 1 :]


def test_assumption_matrix_userid(local_matrix_servers):
    client = create_logged_in_client(local_matrix_servers[0])

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
    new_client = create_logged_in_client(local_matrix_servers[0])
    user = User(client.api, new_client.user_id)
    user.get_display_name()
