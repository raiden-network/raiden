from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Union

import canonicaljson
from eth_typing import ChecksumAddress
from eth_utils import keccak, to_canonical_address, to_checksum_address
from marshmallow import EXCLUDE, post_dump, post_load

from raiden.messages.abstract import cached_property
from raiden.storage.serialization import serializer
from raiden.utils.typing import (
    Address,
    AddressMetadata,
    Dict,
    EncryptedSecret,
    List,
    MetadataHash,
    Optional,
)
from raiden.utils.validation import MetadataValidation


@dataclass
class RouteMetadata(MetadataValidation):
    route: List[Address]
    address_metadata: Optional[Dict[Address, AddressMetadata]] = None

    class Meta:
        """
        Sets meta-options for the Schema as defined in
        raiden.storage.serialization.schema.BaseSchemaOpts and the standard marshmallow options.

        """

        unknown = EXCLUDE
        # Don't include optional fields that are None during dumping
        serialize_missing = False

    def __post_init__(
        self,
    ) -> None:
        # don't use the original object, since this would result in mutated state
        self.address_metadata = deepcopy(self.address_metadata)
        self._validate_address_metadata()

    def _validate_address_metadata(self) -> None:
        validation_errors = self.validate_address_metadata()
        if self.address_metadata is not None:
            for address in validation_errors:
                del self.address_metadata[address]

    def get_metadata(self) -> Optional[Dict[Address, AddressMetadata]]:
        return self.address_metadata

    def __repr__(self) -> str:
        return f"RouteMetadata: {' -> '.join([to_checksum_address(a) for a in self.route])}"


@dataclass(frozen=True)
class Metadata:
    """
    Metadata is used by nodes to provide following hops in a transfer with additional information,
    e.g. to make additonal optimizations possible.
    It can contain arbitrary data and should be considered a read-only datastructure
    for mediating nodes.

    For mediating / target nodes, the original datastructure as sent out by a previous node
    is memorized in original_data.

    All other attributes are attributes that our node can use internally.
    If an additional attribute is required (non-`Optional`) this means that our node requires
    this information from the previous node in order to successfully continue the payment.
    Therefore a strategy for error recovery has to be implemented upon deserialization, in the
    case that these attributes are lacking.

    Note for serialization:
    If there is `original_data` present in the object, as per the `_post_dump` other attributes
    on the object (e.g. `routes`) will not get dumped, and thus only the original_data will get
    persisted, e.g. upon dumping to the WAL!
    """

    # Providing routes is required for forwarding transfers and as a mediator we don't want to
    # accept transfer where we would have to eventually pay the PFS for a path-request.
    routes: List[RouteMetadata]
    # `original_data` is the JSON decoded Metadata as received from a node.
    # The absence of this attribute is implying that we are the ones to
    # inititally create the Metadata object as part of a message - this is the case when we are
    # the initiator of a transfer.
    original_data: Optional[Any] = None
    encrypted_secret: Optional[EncryptedSecret] = None
    _hash: Optional[MetadataHash] = None

    class Meta:
        """
        Sets meta-options for the Schema as defined in
        raiden.storage.serialisation.schema.BaseSchemaOpts and the standard marshmallow options.

        """

        unknown = EXCLUDE
        serialize_missing = False

    @cached_property
    def hash(self) -> MetadataHash:
        if self._hash is not None:
            return self._hash
        return MetadataHash(keccak(self._serialize_canonical()))

    @post_load(pass_original=True, pass_many=True)
    def _post_load(  # pylint: disable=no-self-use,unused-argument
        self, data: Dict[str, Any], original_data: Dict[str, Any], many: bool, **kwargs: Any
    ) -> Dict[str, Any]:
        data["original_data"] = original_data
        return data

    @post_dump(pass_many=True)
    def _post_dump(  # pylint: disable=no-self-use,unused-argument
        self, data: Dict[str, Any], many: bool
    ) -> Dict[str, Any]:
        """
        `original_data` means we received the metadata (Mediator/Target) and read in the data
        for internal processing, so once we pass them to the next node just dump the data exactly
        as we received them.

        Returning `data` means we initially created the Metadata (Initiator), so dump the known
        fields as per the Schema
        """
        dumped_data = data.pop("original_data", None) or data
        dumped_data.pop("_hash", None)
        return dumped_data

    def __repr__(self) -> str:
        return f"Metadata: routes: {[repr(route) for route in self.routes]}"

    def to_dict(self) -> Dict[str, Any]:
        data = serializer.DictSerializer.serialize(self)
        serializer.remove_type_inplace(data)
        return data

    def _serialize_canonical(self) -> bytes:
        data = self.to_dict()
        return canonicaljson.encode_canonical_json(data)


def hash_metadata_v2_0_0(metadata: Metadata) -> MetadataHash:
    legacy_routes = []

    for route_metadata in metadata.routes:
        route = [
            to_checksum_address(to_canonical_address(address)) for address in route_metadata.route
        ]
        # We add a default value of {} when validating. Normalize this to
        # no key when signing.
        canonical_route_dict: Dict[
            str,
            Union[
                List[ChecksumAddress],
                Dict[ChecksumAddress, AddressMetadata],
            ],
        ] = {"route": route}
        if route_metadata.address_metadata is not None:

            address_metadata = {
                to_checksum_address(to_canonical_address(address)): metadata
                for address, metadata in route_metadata.address_metadata.items()
            }
            canonical_route_dict["address_metadata"] = address_metadata

        legacy_routes.append(canonical_route_dict)

    return MetadataHash(keccak(canonicaljson.encode_canonical_json({"routes": legacy_routes})))
