import random
from typing import List, Optional

import pytest

from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX
from raiden.messages.transfers import SecretRequest
from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix.client import Room
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.mocks import MockRaidenService
from raiden.utils import Address
from raiden.utils.signer import LocalSigner

USERID0 = "@0x1234567890123456789012345678901234567890:RestaurantAtTheEndOfTheUniverse"
USERID1 = "@0x0987654321098765432109876543210987654321:Wonderland"


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


@pytest.fixture
def mock_matrix(monkeypatch, retry_interval, retries_before_backoff):

    from raiden.network.transport.matrix.client import GMatrixClient, User
    from raiden.network.transport.matrix.utils import UserPresence
    from raiden.network.transport.matrix import transport as transport_module

    monkeypatch.setattr(User, "get_display_name", lambda _: "random_display_name")
    monkeypatch.setattr(
        transport_module, "make_client", lambda url, *a, **kw: GMatrixClient(url[0])
    )

    def mock_get_room_ids_for_address(  # pylint: disable=unused-argument
        klass, address: Address
    ) -> List[str]:
        return ["!roomID:server"]

    def mock_set_room_id_for_address(  # pylint: disable=unused-argument
        self, address: Address, room_id: Optional[str]
    ):
        pass

    def mock_receive_message(klass, message):  # pylint: disable=unused-argument
        # We are just unit testing the matrix transport receive so do nothing
        assert message
        assert message.sender

    def mock_get_user_presence(self, user_id: str):
        return UserPresence.ONLINE

    config = dict(
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        server="http://none",
        server_name="none",
        available_servers=[],
        broadcast_rooms=[],
    )

    transport = MatrixTransport(config)
    transport._raiden_service = MockRaidenService()
    transport._stop_event.clear()
    transport._address_mgr.add_userid_for_address(factories.HOP1, USERID1)
    transport._client.user_id = USERID0

    monkeypatch.setattr(
        MatrixTransport, "_get_room_ids_for_address", mock_get_room_ids_for_address
    )
    monkeypatch.setattr(MatrixTransport, "_set_room_id_for_address", mock_set_room_id_for_address)
    monkeypatch.setattr(MatrixTransport, "_receive_message", mock_receive_message)
    monkeypatch.setattr(GMatrixClient, "get_user_presence", mock_get_user_presence)

    return transport


def make_message(sign=True, overwrite_data=None):
    room = Room(None, "!roomID:server")
    if not overwrite_data:
        message = SecretRequest(
            message_identifier=random.randint(0, UINT64_MAX),
            payment_identifier=1,
            secrethash=factories.UNIT_SECRETHASH,
            amount=1,
            expiration=10,
            signature=EMPTY_SIGNATURE,
        )
        if sign:
            message.sign(LocalSigner(factories.HOP1_KEY))
        data = MessageSerializer.serialize(message)
    else:
        data = overwrite_data

    event = dict(
        type="m.room.message", sender=USERID1, content={"msgtype": "m.text", "body": data}
    )
    return room, event


def test_normal_processing_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    room, event = make_message()
    assert mock_matrix._handle_message(room, event)


def test_processing_invalid_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    invalid_json = '{"foo": 1,'
    room, event = make_message(overwrite_data=invalid_json)
    assert not mock_matrix._handle_message(room, event)


def test_non_signed_message_is_rejected(
    mock_matrix, skip_userid_validation
):  # pylint: disable=unused-argument
    room, event = make_message(sign=False)
    assert not mock_matrix._handle_message(room, event)


def test_sending_nonstring_body(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    room, event = make_message(overwrite_data=b"somebinarydata")
    assert not mock_matrix._handle_message(room, event)


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
    room, event = make_message(overwrite_data=message_input)
    assert not mock_matrix._handle_message(room, event)


def test_processing_invalid_message_type_json(  # pylint: disable=unused-argument
    mock_matrix, skip_userid_validation
):
    invalid_message = '{"_type": "NonExistentMessage", "is": 3, "not_valid": 5}'
    room, event = make_message(overwrite_data=invalid_message)
    assert not mock_matrix._handle_message(room, event)
