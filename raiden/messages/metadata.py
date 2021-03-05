from dataclasses import dataclass

import rlp
from eth_utils import keccak

from raiden.messages.abstract import cached_property
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, Any, AddressMetadata, Dict, List


def primitive_dict_to_nested_lists(dic) -> List[Any]:
    serialized_dict = list()
    for k, v in sorted(dic.items()):
        if isinstance(v, dict):
            v = primitive_dict_to_nested_lists(v)
        serialized_dict.append([k, v])
    return serialized_dict


@dataclass(frozen=True)
class RouteMetadata:
    route: List[Address]
    address_metadata: Dict[Address, AddressMetadata]

    @cached_property
    def hash(self) -> bytes:
        return keccak(self._rlp_serialize())

    def _rlp_serialize(self) -> bytes:
        return rlp.encode(
            primitive_dict_to_nested_lists(
                {"route": self.route, "address_metadata": self.address_metadata}
            )
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
