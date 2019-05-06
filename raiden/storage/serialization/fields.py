from random import Random

import marshmallow
from eth_utils import to_canonical_address, to_checksum_address

from raiden.utils.serialization import to_bytes, to_hex
from raiden.utils.typing import Address, Any, Tuple


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
