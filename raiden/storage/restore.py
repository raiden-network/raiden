from eth_utils import to_checksum_address, to_hex

from raiden.exceptions import RaidenUnrecoverableError
from raiden.storage.sqlite import EventRecord, SQLiteStorage, StateChangeRecord
from raiden.storage.wal import restore_to_state_change
from raiden.transfer import node, views
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import NettingChannelState
from raiden.utils.typing import (
    Address,
    Any,
    BalanceHash,
    Dict,
    Locksroot,
    Optional,
    StateChangeID,
    Union,
)


def channel_state_until_state_change(
    raiden,
    canonical_identifier: CanonicalIdentifier,
    state_change_identifier: Union[StateChangeID, str],
) -> Optional[NettingChannelState]:
    """ Go through WAL state changes until a certain balance hash is found. """
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
    storage: SQLiteStorage,
    canonical_identifier: CanonicalIdentifier,
    balance_hash: BalanceHash,
    sender: Address,
) -> Optional[StateChangeRecord]:
    """ Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    return storage.get_latest_state_change_by_data_field(
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


def get_state_change_with_balance_proof_by_locksroot(
    storage: SQLiteStorage,
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
    return storage.get_latest_state_change_by_data_field(
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


def get_event_with_balance_proof_by_balance_hash(
    storage: SQLiteStorage, canonical_identifier: CanonicalIdentifier, balance_hash: BalanceHash
) -> Optional[EventRecord]:
    """ Returns the event which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    filters = {
        "canonical_identifier.chain_identifier": str(canonical_identifier.chain_identifier),
        "canonical_identifier.token_network_address": to_checksum_address(
            canonical_identifier.token_network_address
        ),
        "canonical_identifier.channel_identifier": str(canonical_identifier.channel_identifier),
        "balance_hash": to_hex(balance_hash),
    }

    event = storage.get_latest_event_by_data_field(
        balance_proof_query_from_keys(prefix="", filters=filters)
    )
    if event is not None:
        return event

    event = storage.get_latest_event_by_data_field(
        balance_proof_query_from_keys(prefix="transfer.", filters=filters)
    )
    return event


def get_event_with_balance_proof_by_locksroot(
    storage: SQLiteStorage,
    canonical_identifier: CanonicalIdentifier,
    locksroot: Locksroot,
    recipient: Address,
) -> Optional[EventRecord]:
    """ Returns the event which contains the corresponding balance proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    filters = {"recipient": to_checksum_address(recipient)}
    balance_proof_filters = balance_proof_query_from_keys(
        prefix="",
        filters={
            "canonical_identifier.chain_identifier": str(canonical_identifier.chain_identifier),
            "canonical_identifier.token_network_address": to_checksum_address(
                canonical_identifier.token_network_address
            ),
            "canonical_identifier.channel_identifier": str(
                canonical_identifier.channel_identifier
            ),
            "locksroot": to_hex(locksroot),
        },
    )
    balance_proof_filters.update(filters)

    event = storage.get_latest_event_by_data_field(balance_proof_filters)
    if event is not None:
        return event

    balance_proof_filters = balance_proof_query_from_keys(
        prefix="transfer.",
        filters={
            "canonical_identifier.chain_identifier": str(canonical_identifier.chain_identifier),
            "canonical_identifier.token_network_address": to_checksum_address(
                canonical_identifier.token_network_address
            ),
            "canonical_identifier.channel_identifier": str(
                canonical_identifier.channel_identifier
            ),
            "locksroot": to_hex(locksroot),
        },
    )
    balance_proof_filters.update(filters)
    event = storage.get_latest_event_by_data_field(balance_proof_filters)
    return event


def balance_proof_query_from_keys(prefix: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    transformed_filters = {}
    for key, value in filters.items():
        transformed_filters[f"{prefix}balance_proof.{key}"] = value
    return transformed_filters
