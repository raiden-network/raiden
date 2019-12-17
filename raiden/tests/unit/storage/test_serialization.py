from pathlib import Path

import marshmallow
import pytest

from raiden.storage.serialization import JSONSerializer
from raiden.storage.serialization.fields import (
    AddressField,
    BytesField,
    IntegerToStringField,
    OptionalIntegerToStringField,
    QueueIdentifierField,
)
from raiden.storage.sqlite import RAIDEN_DB_VERSION, SerializedSQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.events import (
    SendWithdrawConfirmation,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.state_change import Block
from raiden.utils.typing import BlockExpiration, BlockGasLimit, BlockNumber, Nonce, WithdrawAmount


def assert_roundtrip(field, value):
    serialized = field._serialize(value, None, None)
    assert field._deserialize(serialized, None, None) == value


@pytest.fixture()
def queue_identifier():
    return QueueIdentifier(
        recipient=factories.make_address(),
        canonical_identifier=factories.make_canonical_identifier(),
    )


def test_queue_identifier_field_roundtrip(queue_identifier):
    assert_roundtrip(QueueIdentifierField(), queue_identifier)


def test_queue_identifier_field_invalid_inputs(queue_identifier):
    serialized = QueueIdentifierField()._serialize(queue_identifier, None, None)
    wrong_delimiter = serialized.replace("|", ":")

    # TODO check for address and chain/channel id validity in QueueIdentifier too, add tests here

    for string in (wrong_delimiter,):
        with pytest.raises(marshmallow.exceptions.ValidationError):
            QueueIdentifierField()._deserialize(string, None, None)


def test_deserialize_raises_validation_error_on_dict():
    for field in [
        IntegerToStringField(),
        OptionalIntegerToStringField(),
        BytesField(),
        AddressField(),
        QueueIdentifierField(),
    ]:
        with pytest.raises(marshmallow.exceptions.ValidationError):
            field._deserialize({}, None, None)


def test_optional_integer_to_string_field_roundtrip():
    field = OptionalIntegerToStringField()
    assert_roundtrip(field, 42)
    assert_roundtrip(field, None)


def test_bytes_field_roundtrip():
    field = BytesField()
    assert_roundtrip(field, b"foo")
    assert_roundtrip(field, b"")
    assert_roundtrip(field, None)


def test_events_loaded_from_storage_should_deserialize(tmp_path):
    filename = Path(f"{tmp_path}/v{RAIDEN_DB_VERSION}_log.db")
    storage = SerializedSQLiteStorage(filename, serializer=JSONSerializer())

    # Satisfy the foreign-key constraint for state change ID
    ids = storage.write_state_changes(
        [
            Block(
                block_number=BlockNumber(1),
                gas_limit=BlockGasLimit(1),
                block_hash=factories.make_block_hash(),
            )
        ]
    )

    canonical_identifier = factories.make_canonical_identifier()
    recipient = factories.make_address()
    participant = factories.make_address()
    event = SendWithdrawRequest(
        recipient=recipient,
        canonical_identifier=canonical_identifier,
        message_identifier=factories.make_message_identifier(),
        total_withdraw=WithdrawAmount(1),
        participant=participant,
        expiration=BlockExpiration(10),
        nonce=Nonce(15),
    )
    storage.write_events([(ids[0], event)])

    stored_events = storage.get_events()
    assert stored_events[0] == event


def test_restore_queueids_to_queues(chain_state, netting_channel_state):
    """ Test that withdraw messages are restorable if they exist in
    chain_state.queueids_to_queues.
    """
    recipient = netting_channel_state.partner_state.address

    queue_identifier = QueueIdentifier(
        recipient=recipient, canonical_identifier=netting_channel_state.canonical_identifier
    )

    msg_args = dict(
        recipient=recipient,
        canonical_identifier=netting_channel_state.canonical_identifier,
        message_identifier=factories.make_message_identifier(),
        total_withdraw=WithdrawAmount(1),
        participant=recipient,
        expiration=BlockExpiration(10),
        nonce=Nonce(15),
    )
    messages = [
        SendWithdrawRequest(**msg_args),
        SendWithdrawConfirmation(**msg_args),
        SendWithdrawExpired(**msg_args),
    ]

    chain_state.queueids_to_queues[queue_identifier] = messages

    serialized_chain_state = JSONSerializer.serialize(chain_state)

    deserialized_chain_state = JSONSerializer.deserialize(serialized_chain_state)

    assert chain_state == deserialized_chain_state
