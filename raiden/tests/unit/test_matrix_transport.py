import json
import pytest
import random
from typing import Union, Optional

from raiden.constants import UINT64_MAX
from raiden.messages import SecretRequest
from raiden.network.transport.matrix import MatrixTransport
from raiden.utils.typing import Address

from raiden.tests.utils.factories import ADDR, UNIT_SECRETHASH, HOP1_KEY, HOP1
from raiden.tests.utils.transport import MockRaidenService


USERID1 = '@Alice:Wonderland'


@pytest.fixture
def mock_matrix(
        monkeypatch,
        retry_interval,
        retries_before_backoff,
):

    from matrix_client.user import User
    monkeypatch.setattr(User, 'get_display_name', lambda _: 'random_display_name')

    def mock_get_user(klass, user: Union[User, str]) -> User:
        return User(None, USERID1)

    def mock_get_room_id_for_address(klass, address: Address) -> Optional[str]:
        return '42'

    def mock_set_room_id_for_address(self, address: Address, room_id: Optional[str]):
        pass

    def mock_receive_message(klass, message):
        # We are just unit testing the matrix transport receive so do nothing
        assert message

    def mock_receive_delivered(klass, delivered):
        # We are just unit testing the matrix transport receive so do nothing
        assert delivered

    config = dict(
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        server='auto',
        available_servers=[
            'https://transport01.raiden.network',
            'https://transport02.raiden.network',
            'https://transport03.raiden.network',
        ],
        discovery_room={
            'alias_fragment': 'discovery',
            'server': 'transport01.raiden.network',
        },
    )

    transport = MatrixTransport(config)
    transport.raiden = MockRaidenService(ADDR)
    transport._stop_event.clear()
    transport._address_to_userids[HOP1] = USERID1

    monkeypatch.setattr(MatrixTransport, '_get_user', mock_get_user)
    monkeypatch.setattr(MatrixTransport, '_get_room_id_for_address', mock_get_room_id_for_address)
    monkeypatch.setattr(MatrixTransport, '_set_room_id_for_address', mock_set_room_id_for_address)
    monkeypatch.setattr(MatrixTransport, '_receive_message', mock_receive_message)

    return transport


@pytest.fixture()
def skip_userid_validation(monkeypatch):
    def mock_validate_userid_signature(klass, user):
        return HOP1

    monkeypatch.setattr(
        MatrixTransport,
        '_validate_userid_signature',
        mock_validate_userid_signature,
    )


def make_message(convert_to_hex: bool = False, overwrite_data=None):
    from matrix_client.room import Room
    room = Room(None, '!roomID:server')
    if not overwrite_data:
        message = SecretRequest(
            message_identifier=random.randint(0, UINT64_MAX),
            payment_identifier=1,
            secrethash=UNIT_SECRETHASH,
            amount=1,
            expiration=10,
        )
        message.sign(HOP1_KEY)
        data = message.encode()
        if convert_to_hex:
            data = '0x' + data.hex()
        else:
            data = json.dumps(message.to_dict())
    else:
        data = overwrite_data

    event = dict(
        type='m.room.message',
        sender=USERID1,
        content={
            'msgtype': 'm.text',
            'body': data,
        },
    )
    return room, event


def test_normal_processing_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    assert m._handle_message(room, event)


def test_normal_processing_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=False)
    assert m._handle_message(room, event)


def test_processing_invalid_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    invalid_json = '{"foo": 1,'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_json)
    assert not m._handle_message(room, event)


def test_sending_nonstring_body(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(overwrite_data=b'somebinarydata')
    assert not m._handle_message(room, event)


def test_processing_invalid_message_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    invalid_message = '{"this": 1, "message": 5, "is": 3, "not_valid": 5}'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_message)
    assert not m._handle_message(room, event)


def test_processing_invalid_message_cmdid_json(mock_matrix, skip_userid_validation):
    m = mock_matrix
    invalid_message = '{"type": "NonExistentMessage", "is": 3, "not_valid": 5}'
    room, event = make_message(convert_to_hex=False, overwrite_data=invalid_message)
    assert not m._handle_message(room, event)


def test_processing_invalid_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = old_data[:-1]
    assert not m._handle_message(room, event)


def test_processing_invalid_message_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = old_data[:-4]
    assert not m._handle_message(room, event)


def test_processing_invalid_message_cmdid_hex(mock_matrix, skip_userid_validation):
    m = mock_matrix
    room, event = make_message(convert_to_hex=True)
    old_data = event['content']['body']
    event['content']['body'] = '0xff' + old_data[4:]
    assert not m._handle_message(room, event)
