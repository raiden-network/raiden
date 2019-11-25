from dataclasses import dataclass

import rlp
from eth_utils import to_checksum_address

from raiden.utils import sha3
from raiden.utils.typing import Address, List


@dataclass(frozen=True)
class RouteMetadata:
    route: List[Address]

    @property
    def hash(self) -> bytes:
        return sha3(rlp.encode(self.route))

    def __repr__(self) -> str:
        return f"RouteMetadata: {' -> '.join([to_checksum_address(a) for a in self.route])}"


@dataclass(frozen=True)
class Metadata:
    routes: List[RouteMetadata]

    @property
    def hash(self) -> bytes:
        return sha3(rlp.encode([r.hash for r in self.routes]))

    def __repr__(self) -> str:
        return f"Metadata: routes: {[repr(route) for route in self.routes]}"
