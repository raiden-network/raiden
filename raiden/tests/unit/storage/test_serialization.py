import pytest

from raiden.storage.serialization.fields import (
    BytesField,
    OptionalIntegerToStringField,
    QueueIdentifierField,
)
from raiden.tests.utils import factories
from raiden.transfer.identifiers import QueueIdentifier


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
