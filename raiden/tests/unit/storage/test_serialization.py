from raiden.storage.serialization.fields import OptionalIntegerToStringField, QueueIdentifierField
from raiden.tests.utils import factories
from raiden.transfer.identifiers import QueueIdentifier


def assert_roundtrip(field, value):
    serialized = field._serialize(value, None, None)
    assert field._deserialize(serialized, None, None) == value


def test_queue_identifier_field_roundtrip():
    queue_identifier = QueueIdentifier(
        recipient=factories.make_address(),
        canonical_identifier=factories.make_canonical_identifier(),
    )
    assert_roundtrip(QueueIdentifierField(), queue_identifier)


def test_optional_integer_to_string_field_roundtrip():
    field = OptionalIntegerToStringField()
    assert_roundtrip(field, 42)
    assert_roundtrip(field, None)
