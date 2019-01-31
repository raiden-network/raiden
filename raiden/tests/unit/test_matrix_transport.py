from unittest.mock import Mock

from matrix_client.errors import MatrixRequestError
from matrix_client.room import Room

from raiden.network.transport.utils import matrix_join_global_room


def test_matrix_join_global_room():
    """ matrix_join_global_room should try joining, fail and then create global public room """
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

    room = matrix_join_global_room(
        client=client,
        name=room_name,
        servers=['https://invalid.server'],
    )
    assert client.join_room.call_count == 2  # room not found on own and invalid servers
    client.create_room.assert_called_once_with(room_name, is_public=True)  # created successfuly
    assert room and isinstance(room, Room)
