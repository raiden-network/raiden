from __future__ import annotations

from enum import Flag, auto
from typing import TYPE_CHECKING, Dict, Optional, Union

from eth_typing import Address

from raiden.utils.typing import AddressMetadata, UserID

if TYPE_CHECKING:
    from raiden.messages.metadata import RouteMetadata
    from raiden.transfer.state import RouteState


class MetadataValidationError(Flag):
    USER_ID_MISSING = auto()
    DISPLAY_NAME_MISSING = auto()
    INVALID_SIGNATURE = auto()


def validate_address_metadata(
    instance: Union[RouteMetadata, RouteState]
) -> Dict[Address, MetadataValidationError]:
    """Validate address metadata

    This function accepts both ``RouteMetadata`` and ``RouteState`` instances
    and validates their ``address_metadata`` or ``address_to_metadata`` fields
    respectively.

    The rules are:

      - Entirely missing metadata (``None`` or empty ``dict``) are ok
      - If metadata are present both ``user_id`` and ``displayname`` need to be set
      - ``displayname`` needs to be a valid signature for ``user_id``

    Returns a dictionary of address to validation error flags.
    """

    # Yay, circular imports
    from raiden.messages.metadata import RouteMetadata
    from raiden.network.transport.matrix.utils import validate_user_id_signature
    from raiden.transfer.state import RouteState

    errors: Dict[Address, MetadataValidationError] = {}

    if isinstance(instance, RouteMetadata):
        metadata = instance.address_metadata
    elif isinstance(instance, RouteState):
        metadata = instance.address_to_metadata
    else:
        raise TypeError(f"Received unexpected instance of type {type(instance)}.")

    if not metadata:
        # Empty metadata are not a failure case
        return errors

    for address in instance.route:
        # Special case for `Flag` instances. There's always a `0` value that represents the absence
        # of a Flag
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
