from dataclasses import dataclass, field

import canonicaljson
import rlp
from eth_utils import keccak

from raiden.messages.abstract import cached_property
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, AddressMetadata, Dict, List


@dataclass(frozen=True)
class RouteMetadata:
    route: List[Address]
    address_metadata: Dict[Address, AddressMetadata] = field(default_factory=dict)

    @cached_property
    def hash(self) -> bytes:
        return keccak(self._serialize_canonicaljson())

    def _serialize_canonicaljson(self) -> bytes:
        route = [to_checksum_address(address) for address in self.route]
        address_metadata = {
            to_checksum_address(address): metadata
            for address, metadata in self.address_metadata.items()
        }
        return canonicaljson.encode_canonical_json(
            {"route": route, "address_metadata": address_metadata}
        )

    def __repr__(self) -> str:
        return f"RouteMetadata: {' -> '.join([to_checksum_address(a) for a in self.route])}"


@dataclass(frozen=True)
class Metadata:
    routes: List[RouteMetadata]

    @cached_property
    def hash(self) -> bytes:
        return keccak(rlp.encode([r.hash for r in self.routes]))

    def __repr__(self) -> str:
        return f"Metadata: routes: {[repr(route) for route in self.routes]}"
