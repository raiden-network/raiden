from dataclasses import dataclass

import canonicaljson
import rlp
from eth_utils import keccak

from raiden.messages.abstract import cached_property
from raiden.network.transport.matrix.utils import validate_user_id_signature
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, AddressMetadata, Dict, List, Optional


class RouteMetadata:
    route: List[Address]
    address_metadata: Optional[Dict[Address, AddressMetadata]]

    def __init__(
        self,
        route: List[Address],
        address_metadata: Optional[Dict[Address, AddressMetadata]] = None,
    ) -> None:
        self.address_metadata = address_metadata or {}
        self.route = route
        self._validate_address_metadata()

    def _validate_address_metadata(self) -> None:
        if self.address_metadata is None:
            return

        for address, metadata in list(self.address_metadata.items()):
            user_id = metadata.get("user_id")
            displayname = metadata.get("displayname")

            if user_id is None or displayname is None:
                del self.address_metadata[address]  # we can't verify this user's identity
                continue

            verified_address = validate_user_id_signature(user_id, displayname)  # type: ignore
            if verified_address != address:
                del self.address_metadata[address]

    @cached_property
    def hash(self) -> bytes:
        return keccak(self._serialize_canonicaljson())

    def _serialize_canonicaljson(self) -> bytes:
        route = [to_checksum_address(address) for address in self.route]
        if self.address_metadata is None:
            address_metadata = None
        else:
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
