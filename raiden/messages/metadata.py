from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

import canonicaljson
import rlp
from eth_utils import keccak
from marshmallow import EXCLUDE, fields, post_dump, post_load

from raiden.messages.abstract import cached_property
from raiden.storage.serialization.serializer import keccak_canonicaljson
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import MYPY_ANNOTATION, Address, AddressMetadata, Dict, List, Optional
from raiden.utils.validation import validate_address_metadata


@dataclass
class RouteMetadata:
    route: List[Address]
    address_metadata: Optional[Dict[Address, AddressMetadata]] = None

    def __post_init__(
        self,
    ) -> None:
        # don't use the original object, since this would result in mutated state
        self.address_metadata = deepcopy(self.address_metadata) or {}
        self._validate_address_metadata()

    def _validate_address_metadata(self) -> None:
        assert self.address_metadata is not None, MYPY_ANNOTATION
        validation_errors = validate_address_metadata(self)
        for address in validation_errors:
            del self.address_metadata[address]

    @cached_property
    def hash(self) -> bytes:
        return keccak_canonicaljson(self)

    def __repr__(self) -> str:
        return f"RouteMetadata: {' -> '.join([to_checksum_address(a) for a in self.route])}"


METADATA_EXTRA = fields.Dict(keys=fields.String, values=fields.Raw())


@dataclass(frozen=True)
class Metadata:
    routes: List[RouteMetadata]
    # The field `_unknown_data` is used to preserve additional metadata
    # fields, that are not in this clients schema, through serialization / deserialization.
    _unknown_data: Optional[Dict[str, List[str]]] = field(
        metadata=dict(marshmallow_field=METADATA_EXTRA, required=False)
    )

    class Meta:
        unknown = EXCLUDE

    @cached_property
    def hash(self) -> bytes:
        return keccak_canonicaljson(self)

    @post_load(pass_original=True)
    def post_loading(
        self,
        data: Dict[str, Any],
        original_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        new_extra_data = {
            k: v
            for k, v in original_data.items()
            if k not in self.declared_fields  # type: ignore # pylint: disable=no-member
        }
        if new_extra_data:
            data["_unknown_data"] = new_extra_data
        return data

    @post_dump
    def post_dump_impl(  # pylint: disable=no-self-use
        self,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        data.update(data.pop("_unknown_data", {}))
        return data

    def __repr__(self) -> str:
        return f"Metadata: routes: {[repr(route) for route in self.routes]}"
