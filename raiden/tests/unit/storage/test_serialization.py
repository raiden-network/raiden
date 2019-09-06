import random

import pytest

from raiden.storage.serialization import JSONSerializer
from raiden.storage.serialization.fields import (
    BytesField,
    OptionalIntegerToStringField,
    QueueIdentifierField,
)
from raiden.storage.sqlite import RAIDEN_DB_VERSION, SerializedSQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.events import SendWithdrawRequest
from raiden.transfer.identifiers import QueueIdentifier
from raiden.transfer.state_change import ActionInitChain


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
        with pytest.raises(ValueError):
            QueueIdentifierField()._deserialize(string, None, None)


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
    filename = f"{tmp_path}/v{RAIDEN_DB_VERSION}_log.db"
    storage = SerializedSQLiteStorage(filename, serializer=JSONSerializer())

    # Satisfy the foreign-key constraint for state change ID
    ids = storage.write_state_changes(
        [
            ActionInitChain(
                pseudo_random_generator=random.Random(),
                block_number=1,
                block_hash=b"",
                our_address=factories.make_address(),
                chain_id=1,
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
        total_withdraw=1,
        participant=participant,
        expiration=10,
        nonce=15,
    )
    storage.write_events([(ids[0], event)])

    stored_events = storage.get_events()
    assert stored_events[0] == event
