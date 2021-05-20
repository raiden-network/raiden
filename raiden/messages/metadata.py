from copy import deepcopy
from dataclasses import dataclass

import canonicaljson
import rlp
from eth_utils import keccak

from raiden.messages.abstract import cached_property
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import MYPY_ANNOTATION, Address, AddressMetadata, Dict, List, Optional
from raiden.utils.validation import validate_address_metadata


class RouteMetadata:
    route: List[Address]
    address_metadata: Optional[Dict[Address, AddressMetadata]]

    def __init__(
        self,
        route: List[Address],
        address_metadata: Optional[Dict[Address, AddressMetadata]] = None,
    ) -> None:

        self.address_metadata = deepcopy(address_metadata) or {}
        self.route = route
        self._validate_address_metadata()

    def _validate_address_metadata(self) -> None:
        assert self.address_metadata is not None, MYPY_ANNOTATION
        validation_errors = validate_address_metadata(self)
        for address in validation_errors:
            del self.address_metadata[address]

    @cached_property
    def hash(self) -> bytes:
        return keccak(self._serialize_canonical())

    def _serialize_canonical(self) -> bytes:
        if not self.address_metadata:
            return rlp.encode(self.route)

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
