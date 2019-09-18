import json
from random import Random
from typing import Callable

import marshmallow
import networkx
from eth_utils import to_bytes, to_canonical_address, to_checksum_address, to_hex
from marshmallow_polyfield import PolyField

from raiden.transfer.identifiers import CanonicalIdentifier, QueueIdentifier
from raiden.utils.typing import Address, Any, ChainID, ChannelID, Optional, Tuple


class IntegerToStringField(marshmallow.fields.Field):
    def _serialize(self, value: int, attr: Any, obj: Any, **kwargs: Any) -> str:
        return str(value)

    def _deserialize(self, value: str, attr: Any, data: Any, **kwargs: Any) -> int:
        return int(value)


class OptionalIntegerToStringField(marshmallow.fields.Field):
    def _serialize(self, value: Optional[int], attr: Any, obj: Any, **kwargs: Any) -> str:
        if value is None:
            return ""
        return str(value)

    def _deserialize(self, value: str, attr: Any, data: Any, **kwargs: Any) -> Optional[int]:
        if value == "":
            return None
        return int(value)


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
        return to_bytes(hexstr=value)


class AddressField(marshmallow.fields.Field):
    """ Converts addresses from bytes to hex and vice versa """

    def _serialize(self, value: Address, attr: Any, obj: Any, **kwargs: Any) -> str:
        return to_checksum_address(value)

    def _deserialize(self, value: str, attr: Any, data: Any, **kwargs: Any) -> Address:
        return to_canonical_address(value)


class QueueIdentifierField(marshmallow.fields.Field):
    """ Converts QueueIdentifier objects to a tuple """

    @staticmethod
    def _canonical_id_from_string(string: str) -> CanonicalIdentifier:
        try:
            chain_id_str, token_network_address_hex, channel_id_str = string.split("|")
            return CanonicalIdentifier(
                chain_identifier=ChainID(int(chain_id_str)),
                token_network_address=to_bytes(hexstr=token_network_address_hex),
                channel_identifier=ChannelID(int(channel_id_str)),
            )
        except ValueError:
            raise ValueError(f"Could not reconstruct canonical identifier from string: {string}")

    @staticmethod
    def _canonical_id_to_string(canonical_id: CanonicalIdentifier) -> str:
        return (
            f"{canonical_id.chain_identifier}|"
            f"{to_checksum_address(canonical_id.token_network_address)}|"
            f"{canonical_id.channel_identifier}"
        )

    def _serialize(
        self, queue_identifier: QueueIdentifier, attr: Any, obj: Any, **kwargs: Any
    ) -> str:
        return (
            f"{to_checksum_address(queue_identifier.recipient)}"
            f"-{self._canonical_id_to_string(queue_identifier.canonical_identifier)}"
        )

    def _deserialize(
        self, queue_identifier_str: str, attr: Any, data: Any, **kwargs: Any
    ) -> QueueIdentifier:
        str_recipient, str_canonical_id = queue_identifier_str.split("-")
        return QueueIdentifier(
            to_canonical_address(str_recipient), self._canonical_id_from_string(str_canonical_id)
        )


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
        return self.pseudo_random_generator_from_json(data)


class CallablePolyField(PolyField):
    def __init__(
        self,
        serialization_schema_selector: Callable = None,
        deserialization_schema_selector: Callable = None,
        many: bool = False,
        **metadata: Any,
    ):
        super().__init__(
            serialization_schema_selector=serialization_schema_selector,
            deserialization_schema_selector=deserialization_schema_selector,
            many=many,
            **metadata,
        )

    def __call__(self, **metadata: Any) -> "CallablePolyField":
        self.metadata = metadata
        return self


class NetworkXGraphField(marshmallow.fields.Field):
    """ Converts networkx.Graph objects to a string """

    def _serialize(self, graph: networkx.Graph, attr: Any, obj: Any, **kwargs: Any) -> str:
        return json.dumps(
            [(to_checksum_address(edge[0]), to_checksum_address(edge[1])) for edge in graph.edges]
        )

    def _deserialize(self, graph_data: str, attr: Any, data: Any, **kwargs: Any) -> networkx.Graph:
        raw_data = json.loads(graph_data)
        canonical_addresses = [
            (to_canonical_address(edge[0]), to_canonical_address(edge[1])) for edge in raw_data
        ]
        return networkx.Graph(canonical_addresses)
