from random import Random

import marshmallow
from eth_utils import to_canonical_address, to_checksum_address
from marshmallow_polyfield import PolyField

from raiden.transfer.identifiers import QueueIdentifier
from raiden.utils.serialization import to_bytes, to_hex
from raiden.utils.typing import Address, Any, ChannelID, Tuple


class IntegerToStringField(marshmallow.fields.Field):
    def _serialize(self, value: int, attr: Any, obj: Any) -> str:
        return str(value)

    def _deserialize(self, value: str, attr: Any, data: Any) -> int:
        return int(value)


class BytesField(marshmallow.fields.Field):
    """ Used for `bytes` in the dataclass, serialize to hex encoding"""

    def _serialize(self, value: bytes, attr: Any, obj: Any) -> str:
        return to_hex(value)

    def _deserialize(self, value: str, attr: Any, data: Any) -> bytes:
        return to_bytes(hexstr=value)


class AddressField(marshmallow.fields.Field):
    """ Converts addresses from bytes to hex and vice versa """

    def _serialize(self, value: Address, attr: Any, obj: Any) -> str:
        return to_checksum_address(value)

    def _deserialize(self, value: str, attr: Any, data: Any) -> Address:
        return to_canonical_address(value)


class QueueIdentifierField(marshmallow.fields.Field):
    """ Converts QueueIdentifier objects to a tuple """

    def _serialize(self, queue_identifier: QueueIdentifier, attr: Any, obj: Any) -> str:
        return (
            f"{to_checksum_address(queue_identifier.recipient)}"
            f"-{str(queue_identifier.channel_identifier)}"
        )

    def _deserialize(self, queue_identifier_str: str, attr: Any, data: Any) -> QueueIdentifier:
        str_recipient, str_channel_id = queue_identifier_str.split("-")
        return QueueIdentifier(to_canonical_address(str_recipient), ChannelID(int(str_channel_id)))


class PRNGField(marshmallow.fields.Field):
    """ Serialization for instances of random.Random. """

    @staticmethod
    def pseudo_random_generator_from_json(data: Any) -> Random:
        # JSON serializes a tuple as a list
        pseudo_random_generator = Random()
        state = list(data["pseudo_random_generator"])  # copy
        state[1] = tuple(state[1])  # fix type
        pseudo_random_generator.setstate(tuple(state))

        return pseudo_random_generator

    def _serialize(self, value: Random, attr: Any, obj: Any) -> Tuple[Any, ...]:
        return value.getstate()

    def _deserialize(self, value: str, attr: Any, data: Any) -> Random:
        return self.pseudo_random_generator_from_json(data)


class CallablePolyField(PolyField):
    def __init__(
        self,
        serialization_schema_selector=None,
        deserialization_schema_selector=None,
        many=False,
        **metadata,
    ):
        super().__init__(
            serialization_schema_selector=serialization_schema_selector,
            deserialization_schema_selector=deserialization_schema_selector,
            many=many,
            **metadata,
        )

    def __call__(self, **metadata):
        self.metadata = metadata
        return self
