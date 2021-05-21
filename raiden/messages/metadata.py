from copy import deepcopy
from dataclasses import dataclass

import canonicaljson
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

    def _canonical_dict(self) -> dict:
        """Return a dict that can be dumped as json

        Used to build signatures.
        """
        route = [to_checksum_address(address) for address in self.route]
        if not self.address_metadata:
            # We add a default value of {} when validating. Normalize this to
            # no key when signing.
            return {"route": route}

        address_metadata = {
            to_checksum_address(address): metadata
            for address, metadata in self.address_metadata.items()
        }
        return {"route": route, "address_metadata": address_metadata}

    def __repr__(self) -> str:
        return f"RouteMetadata: {' -> '.join([to_checksum_address(a) for a in self.route])}"


@dataclass(frozen=True)
class Metadata:
    routes: List[RouteMetadata]

    @cached_property
    def hash(self) -> bytes:
        return keccak(self._serialize_canonical())

    def __repr__(self) -> str:
        return f"Metadata: routes: {[repr(route) for route in self.routes]}"

    def _serialize_canonical(self) -> bytes:
        return canonicaljson.encode_canonical_json(
            {"routes": [route._canonical_dict() for route in self.routes]}
        )
