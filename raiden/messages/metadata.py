from dataclasses import dataclass

import rlp
from eth_utils import keccak

from raiden.messages.abstract import cached_property
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, List


@dataclass(frozen=True)
class RouteMetadata:
    route: List[Address]

    @cached_property
    def hash(self) -> bytes:
        return keccak(rlp.encode(self.route))

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
