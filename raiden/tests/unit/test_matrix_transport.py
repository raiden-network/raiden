from unittest.mock import Mock, create_autospec
from urllib.parse import urlparse

from eth_utils import decode_hex, encode_hex, to_canonical_address, to_normalized_address
from matrix_client.errors import MatrixRequestError
from matrix_client.room import Room
from matrix_client.user import User

from raiden.network.transport.matrix.utils import (
    join_global_room,
    login_or_register,
    validate_userid_signature,
)
from raiden.tests.utils.factories import make_signer
from raiden.utils.signer import recover


def test_join_global_room():
    """ join_global_room should try joining, fail and then create global public room """
    ownserver = 'https://ownserver.com'
    api = Mock()
    api.base_url = ownserver

    client = Mock()
    client.api = api

    def create_room(alias, is_public=False, invitees=None):
        room = Room(client, f'!room_id:ownserver.com')
        room.canonical_alias = alias
        return room

    client.create_room = Mock(side_effect=create_room)
    client.join_room = Mock(side_effect=MatrixRequestError(404))

    room_name = 'raiden_ropsten_discovery'

    room = join_global_room(
        client=client,
        name=room_name,
        servers=['https://invalid.server'],
    )
    assert client.join_room.call_count == 2  # room not found on own and invalid servers
    client.create_room.assert_called_once_with(room_name, is_public=True)  # created successfuly
    assert room and isinstance(room, Room)


def test_login_or_register_default_user():
    ownserver = 'https://ownserver.com'
    api = Mock()
    api.base_url = ownserver
    server_name = urlparse(ownserver).netloc

    client = Mock()
    client.api = api

    # login will assert user is hex-encoded address and pw is server_name signed with that address
    def mock_login(user, pw, sync=True):
        recovered = recover(data=server_name.encode(), signature=decode_hex(pw))
        if recovered != to_canonical_address(user):
            raise MatrixRequestError(403)
        client.user_id = f'@{user}:{server_name}'

    client.login = Mock(side_effect=mock_login)

    MockUser = create_autospec(User)

    client.get_user = Mock(side_effect=lambda user_id: MockUser(api, user_id))

    signer = make_signer()

    user = login_or_register(
        client=client,
        signer=signer,
    )

    # client.user_id will be set by login
    assert client.user_id.startswith(f'@{to_normalized_address(signer.address)}')
    # login_or_register returns our own user object
    assert isinstance(user, User)
    # get_user must have been called once to generate above user
    client.get_user.assert_called_once_with(client.user_id)
    # assert set_display_name was called once on ourselves
    assert user.set_display_name.call_count == 1
    # assert the user.set_display_name was called with the signature of the user_id
    assert recover(
        data=client.user_id.encode(),
        signature=decode_hex(user.set_display_name.call_args[0][0]),
    ) == signer.address


def test_validate_userid_signature():
    ownserver = 'https://ownserver.com'
    api = Mock()
    api.base_url = ownserver
    server_name = urlparse(ownserver).netloc

    signer = make_signer()

    user = Mock(spec=User)
    user.api = api
    user.user_id = f'@{to_normalized_address(signer.address)}:{server_name}'
    user.displayname = None
    user.get_display_name = Mock(side_effect=lambda: user.displayname)

    # displayname is None, get_display_name will be called but continue to give None
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 1

    # successfuly recover valid displayname
    user.displayname = encode_hex(signer.sign(user.user_id.encode()))
    assert validate_userid_signature(user) == signer.address
    assert user.get_display_name.call_count == 2

    # assert another call will cache the result and avoid wasteful get_display_name call
    assert validate_userid_signature(user) == signer.address
    assert user.get_display_name.call_count == 2

    # non-hex displayname should be gracefully handled
    user.displayname = 'random gibberish'
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 3

    # valid signature but from another user should also return None
    user.displayname = encode_hex(make_signer().sign(user.user_id.encode()))
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 4

    # same address, but different user_id, even if valid, should be rejected
    # (prevent personification)
    user.displayname = encode_hex(signer.sign(user.user_id.encode()))
    user.user_id = f'@{to_normalized_address(signer.address)}.deadbeef:{server_name}'
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 5

    # but non-default but valid user_id should be accepted
    user.displayname = encode_hex(signer.sign(user.user_id.encode()))
    assert validate_userid_signature(user) == signer.address
    assert user.get_display_name.call_count == 6

    # non-compliant user_id shouldn't even call get_display_name
    user.user_id = f'@my_user:{server_name}'
    assert validate_userid_signature(user) is None
    assert user.get_display_name.call_count == 6
