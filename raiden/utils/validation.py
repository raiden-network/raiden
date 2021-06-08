from __future__ import annotations

from dataclasses import dataclass
from enum import Flag, auto
from typing import Dict, List, Optional

from eth_typing import Address

from raiden.utils.typing import AddressMetadata, UserID


class MetadataValidationError(Flag):
    USER_ID_MISSING = auto()
    DISPLAY_NAME_MISSING = auto()
    INVALID_SIGNATURE = auto()


@dataclass
class MetadataValidation:
    route: List[Address]

    def get_metadata(self) -> Optional[Dict[Address, AddressMetadata]]:
        raise NotImplementedError()

    def validate_address_metadata(self) -> Dict[Address, MetadataValidationError]:
        """Validate address metadata

        The rules are:

          - Entirely missing metadata (``None`` or empty ``dict``) are ok
          - If metadata is present, both ``user_id`` and ``displayname`` need to be set
          - ``displayname`` needs to be a valid signature for ``user_id``

        Returns a dictionary of address to validation error flags.
        """

        # Circular imports
        from raiden.network.transport.matrix.utils import validate_user_id_signature

        errors: Dict[Address, MetadataValidationError] = {}

        metadata = self.get_metadata()

        if not metadata:
            # Empty metadata are not a failure case
            return errors

        for address in self.route:
            # Special case for `Flag` instances.
            # There's always a `0` value that represents the absence of a Flag
            error = MetadataValidationError(0)

            address_metadata: Optional[AddressMetadata] = metadata.get(address)
            if not address_metadata:
                # Missing or empty metadata is currently not a failure case
                continue

            user_id = address_metadata.get("user_id")
            displayname = address_metadata.get("displayname")

            if user_id is None:
                error |= MetadataValidationError.USER_ID_MISSING
            if displayname is None:
                error |= MetadataValidationError.DISPLAY_NAME_MISSING

            if not error:
                verified_address = validate_user_id_signature(
                    UserID(user_id),  # type: ignore
                    displayname,
                )
                if verified_address != address:
                    error |= MetadataValidationError.INVALID_SIGNATURE

            if error:
                errors[address] = error

        return errors
