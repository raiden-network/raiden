import json
from random import Random
from typing import Dict, Iterable

import marshmallow
import networkx
from eth_utils import to_bytes, to_canonical_address, to_hex
from marshmallow import Schema
from marshmallow_polyfield import PolyField

from raiden.storage.serialization.cache import SchemaCache
from raiden.transfer.identifiers import CanonicalIdentifier, QueueIdentifier
from raiden.utils.formatting import to_hex_address
from raiden.utils.typing import (
    Address,
    Any,
    ChainID,
    ChannelID,
    Optional,
    TokenNetworkAddress,
    Tuple,
)


class IntegerToStringField(marshmallow.fields.Integer):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(as_string=True, **kwargs)


class OptionalIntegerToStringField(marshmallow.fields.Integer):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(as_string=True, required=False, **kwargs)


class BytesField(marshmallow.fields.Field):
    """ Used for `bytes` in the dataclass, serialize to hex encoding"""

    def _serialize(
        self, value: Optional[bytes], attr: Any, obj: Any, **kwargs: Any
    ) -> Optional[str]:
        if value is None:
            return value
        return to_hex(value)

    def _deserialize(
        self, value: Optional[str], attr: Any, data: Any, **kwargs: Any
    ) -> Optional[bytes]:
        if value is None:
            return value
        try:
            return to_bytes(hexstr=value)
        except (TypeError, ValueError):
            raise self.make_error("validator_failed", input=value)


class AddressField(marshmallow.fields.Field):
    """ Converts addresses from bytes to hex and vice versa """

    def _serialize(self, value: Address, attr: Any, obj: Any, **kwargs: Any) -> str:
        return to_hex_address(value)

    def _deserialize(self, value: str, attr: Any, data: Any, **kwargs: Any) -> Address:
        try:
            return to_canonical_address(value)
        except (TypeError, ValueError):
            raise self.make_error("validator_failed", input=value)


class QueueIdentifierField(marshmallow.fields.Field):
    """ Converts QueueIdentifier objects to a tuple """

    @staticmethod
    def _canonical_id_from_string(string: str) -> CanonicalIdentifier:
        try:
            chain_id_str, token_network_address_hex, channel_id_str = string.split("|")
            return CanonicalIdentifier(
                chain_identifier=ChainID(int(chain_id_str)),
                token_network_address=TokenNetworkAddress(
                    to_canonical_address(token_network_address_hex)
                ),
                channel_identifier=ChannelID(int(channel_id_str)),
            )
        except ValueError:
            raise ValueError(f"Could not reconstruct canonical identifier from string: {string}")

    @staticmethod
    def _canonical_id_to_string(canonical_id: CanonicalIdentifier) -> str:
        return (
            f"{canonical_id.chain_identifier}|"
            f"{to_hex_address(canonical_id.token_network_address)}|"
            f"{canonical_id.channel_identifier}"
        )

    def _serialize(self, value: QueueIdentifier, attr: Any, obj: Any, **kwargs: Any) -> str:
        return (
            f"{to_hex_address(value.recipient)}"
            f"-{self._canonical_id_to_string(value.canonical_identifier)}"
        )

    def _deserialize(self, value: str, attr: Any, data: Any, **kwargs: Any) -> QueueIdentifier:
        try:
            str_recipient, str_canonical_id = value.split("-")
            return QueueIdentifier(
                to_canonical_address(str_recipient),
                self._canonical_id_from_string(str_canonical_id),
            )
        except (TypeError, ValueError, AttributeError):
            raise self.make_error("validator_failed", input=value)


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

    def _serialize(self, value: Random, attr: Any, obj: Any, **kwargs: Any) -> Tuple[Any, ...]:
        return value.getstate()

    def _deserialize(self, value: str, attr: Any, data: Any, **kwargs: Any) -> Random:
        try:
            return self.pseudo_random_generator_from_json(data)
        except (TypeError, ValueError):
            raise self.make_error("validator_failed", input=value)


class CallablePolyField(PolyField):
    def __init__(self, allowed_classes: Iterable[type], many: bool = False, **metadata: Any):
        super().__init__(many=many, **metadata)
        self._class_of_classname = {cls.__name__: cls for cls in allowed_classes}

    @staticmethod
    def serialization_schema_selector(obj: Any, parent: Any) -> Schema:
        # pylint: disable=unused-argument
        return SchemaCache.get_or_create_schema(obj.__class__)

    def deserialization_schema_selector(
        self, deserializable_dict: Dict[str, Any], parent: Dict[str, Any]
    ) -> Schema:
        # pylint: disable=unused-argument
        type_ = deserializable_dict["_type"].split(".")[-1]
        return SchemaCache.get_or_create_schema(self._class_of_classname[type_])

    def __call__(self, **metadata: Any) -> "CallablePolyField":
        self.metadata = metadata
        return self


class NetworkXGraphField(marshmallow.fields.Field):
    """ Converts networkx.Graph objects to a string """

    def _serialize(self, value: networkx.Graph, attr: Any, obj: Any, **kwargs: Any) -> str:
        return json.dumps(
            [(to_hex_address(edge[0]), to_hex_address(edge[1])) for edge in value.edges]
        )

    def _deserialize(self, value: str, attr: Any, data: Any, **kwargs: Any) -> networkx.Graph:
        try:
            raw_data = json.loads(value)
            canonical_addresses = [
                (to_canonical_address(edge[0]), to_canonical_address(edge[1])) for edge in raw_data
            ]
            return networkx.Graph(canonical_addresses)
        except (TypeError, ValueError):
            raise self.make_error("validator_failed", input=value)
