from dataclasses import dataclass

from eth_utils import to_checksum_address, to_hex

from raiden.constants import EMPTY_HASH, LOCKSROOT_OF_NO_LOCKS
from raiden.exceptions import RaidenUnrecoverableError
from raiden.storage.sqlite import (
    EventRecord,
    FilteredDBQuery,
    Operator,
    SerializedSQLiteStorage,
    StateChangeID,
    StateChangeRecord,
)
from raiden.storage.wal import restore_to_state_change
from raiden.transfer import node, views
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import NettingChannelState
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Any,
    BalanceHash,
    Dict,
    List,
    Locksroot,
    Optional,
)


@dataclass(frozen=True)
class LocksrootRecord:
    partner_locksroot: Locksroot
    our_locksroot: Locksroot


if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService


def channel_state_until_state_change(
    raiden: "RaidenService",
    canonical_identifier: CanonicalIdentifier,
    state_change_identifier: StateChangeID,
) -> Optional[NettingChannelState]:  # pragma: no unittest
    """ Go through WAL state changes until a certain balance hash is found. """
    assert raiden.wal, "Raiden has not been started yet"

    wal = restore_to_state_change(
        transition_function=node.state_transition,
        storage=raiden.wal.storage,
        state_change_identifier=state_change_identifier,
    )

    msg = "There is a state change, therefore the state must not be None"
    assert wal.state_manager.current_state is not None, msg

    chain_state = wal.state_manager.current_state

    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=canonical_identifier
    )

    if not channel_state:
        raise RaidenUnrecoverableError(
            f"Channel was not found before state_change {state_change_identifier}"
        )

    return channel_state


def get_state_change_with_balance_proof_by_balance_hash(
    storage: SerializedSQLiteStorage,
    canonical_identifier: CanonicalIdentifier,
    balance_hash: BalanceHash,
    sender: Address,
) -> Optional[StateChangeRecord]:
    """ Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    filters: List[Dict[str, Any]] = list()
    filters.append(
        {
            "balance_proof.canonical_identifier.chain_identifier": str(
                canonical_identifier.chain_identifier
            ),
            "balance_proof.canonical_identifier.token_network_address": to_checksum_address(
                canonical_identifier.token_network_address
            ),
            "balance_proof.canonical_identifier.channel_identifier": str(
                canonical_identifier.channel_identifier
            ),
            "balance_proof.balance_hash": to_hex(balance_hash),
            "balance_proof.sender": to_checksum_address(sender),
        }
    )

    query = FilteredDBQuery(
        filters=filters, main_operator=Operator.NONE, inner_operator=Operator.AND
    )
    return storage.get_latest_state_change_by_data_field(query)


def get_state_change_with_balance_proof_by_locksroot(
    storage: SerializedSQLiteStorage,
    canonical_identifier: CanonicalIdentifier,
    locksroot: Locksroot,
    sender: Address,
) -> Optional[StateChangeRecord]:
    """ Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    filters: List[Dict[str, Any]] = list()
    filters.append(
        {
            "balance_proof.canonical_identifier.chain_identifier": str(
                canonical_identifier.chain_identifier
            ),
            "balance_proof.canonical_identifier.token_network_address": to_checksum_address(
                canonical_identifier.token_network_address
            ),
            "balance_proof.canonical_identifier.channel_identifier": str(
                canonical_identifier.channel_identifier
            ),
            "balance_proof.locksroot": to_hex(locksroot),
            "balance_proof.sender": to_checksum_address(sender),
        }
    )
    query = FilteredDBQuery(
        filters=filters, main_operator=Operator.NONE, inner_operator=Operator.AND
    )
    return storage.get_latest_state_change_by_data_field(query)


def get_event_with_balance_proof_by_balance_hash(
    storage: SerializedSQLiteStorage,
    canonical_identifier: CanonicalIdentifier,
    balance_hash: BalanceHash,
    recipient: Address,
) -> Optional[EventRecord]:
    """ Returns the event which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    filters: List[Dict[str, Any]] = list()

    filter_items = {
        "canonical_identifier.chain_identifier": str(canonical_identifier.chain_identifier),
        "canonical_identifier.token_network_address": to_checksum_address(
            canonical_identifier.token_network_address
        ),
        "canonical_identifier.channel_identifier": str(canonical_identifier.channel_identifier),
        "balance_hash": to_hex(balance_hash),
    }

    balance_proof_filters = balance_proof_query_from_keys(prefix="", filters=filter_items)
    balance_proof_filters["recipient"] = to_checksum_address(recipient)
    filters.append(balance_proof_filters)

    transfer_filters = balance_proof_query_from_keys(prefix="transfer.", filters=filter_items)
    transfer_filters["recipient"] = to_checksum_address(recipient)
    filters.append(transfer_filters)

    query = FilteredDBQuery(
        filters=filters, main_operator=Operator.OR, inner_operator=Operator.AND
    )

    event = storage.get_latest_event_by_data_field(query)
    return event


def get_event_with_balance_proof_by_locksroot(
    storage: SerializedSQLiteStorage,
    canonical_identifier: CanonicalIdentifier,
    locksroot: Locksroot,
    recipient: Address,
) -> Optional[EventRecord]:
    """ Returns the event which contains the corresponding balance proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    filters: List[Dict[str, Any]] = list()

    filter_items = {
        "canonical_identifier.chain_identifier": str(canonical_identifier.chain_identifier),
        "canonical_identifier.token_network_address": to_checksum_address(
            canonical_identifier.token_network_address
        ),
        "canonical_identifier.channel_identifier": str(canonical_identifier.channel_identifier),
        "locksroot": to_hex(locksroot),
    }
    balance_proof_filters = balance_proof_query_from_keys(prefix="", filters=filter_items)
    balance_proof_filters["recipient"] = to_checksum_address(recipient)
    filters.append(balance_proof_filters)

    transfer_filters = balance_proof_query_from_keys(prefix="transfer.", filters=filter_items)
    transfer_filters["recipient"] = to_checksum_address(recipient)
    filters.append(transfer_filters)

    query = FilteredDBQuery(
        filters=filters, main_operator=Operator.OR, inner_operator=Operator.AND
    )
    event = storage.get_latest_event_by_data_field(query)
    return event


def balance_proof_query_from_keys(prefix: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    transformed_filters = {}
    for key, value in filters.items():
        transformed_filters[f"{prefix}balance_proof.{key}"] = value
    return transformed_filters


def try_to_match_locksroots(
    storage: SerializedSQLiteStorage,
    latest_channel_state: NettingChannelState,
    try_our_locksroot: Locksroot,
    try_partner_locksroot: Locksroot,
) -> Optional[LocksrootRecord]:
    """Search in the database for `try_our_locksroot` and
    `try_partner_locksroot`, if both are match the expected end of the channel
    `latest_channel_state` then LocksrootRecord is returned.

    Notes:
        - The empty hash has to be handled. Because this value is the default,
          it is always assumed to be valid.
        - The locksroot does not have to match the latest state of the channel,
          however it must have been part of some version of the channel. This
          is necessary to handle cases were a malicious node closes the channel
          with older balance proofs, otherwise settling would not be possible.
    """
    our_locksroot = None
    partner_locksroot = None

    if try_our_locksroot == EMPTY_HASH:
        our_locksroot = LOCKSROOT_OF_NO_LOCKS
    else:
        event_record = get_event_with_balance_proof_by_locksroot(
            storage=storage,
            canonical_identifier=latest_channel_state.canonical_identifier,
            locksroot=try_our_locksroot,
            recipient=latest_channel_state.partner_state.address,
        )

        if event_record is not None:
            our_locksroot = try_our_locksroot

    if try_partner_locksroot == EMPTY_HASH:
        partner_locksroot = LOCKSROOT_OF_NO_LOCKS
    else:
        state_change_record = get_state_change_with_balance_proof_by_locksroot(
            storage=storage,
            canonical_identifier=latest_channel_state.canonical_identifier,
            locksroot=try_partner_locksroot,
            sender=latest_channel_state.partner_state.address,
        )

        if state_change_record is not None:
            partner_locksroot = try_partner_locksroot

    if our_locksroot is not None and partner_locksroot is not None:
        return LocksrootRecord(our_locksroot=our_locksroot, partner_locksroot=partner_locksroot)

    return None


def order_locksroot(
    storage: SerializedSQLiteStorage,
    latest_channel_state: NettingChannelState,
    locksroot1: Locksroot,
    locksroot2: Locksroot,
) -> Optional[LocksrootRecord]:
    """Finds order of locksroot1 and locksroot2.

    Returns None if any of the two locksroots is unknown, otherwise return
    LocksrootRecord with the end of the locksroot correctly set.
    """

    order = try_to_match_locksroots(
        storage=storage,
        latest_channel_state=latest_channel_state,
        try_our_locksroot=locksroot1,
        try_partner_locksroot=locksroot2,
    )

    # Try again in the reverse order
    if order is None:
        order = try_to_match_locksroots(
            storage=storage,
            latest_channel_state=latest_channel_state,
            try_our_locksroot=locksroot2,
            try_partner_locksroot=locksroot1,
        )

    return order
