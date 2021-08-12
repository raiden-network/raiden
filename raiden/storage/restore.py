from eth_utils import to_hex

from raiden.exceptions import RaidenUnrecoverableError
from raiden.storage.sqlite import (
    EventRecord,
    FilteredDBQuery,
    Operator,
    SerializedSQLiteStorage,
    StateChangeID,
    StateChangeRecord,
)
from raiden.storage.wal import restore_state
from raiden.transfer import node, views
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import ChainState, NettingChannelState
from raiden.utils.formatting import to_hex_address
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Any,
    BalanceHash,
    Dict,
    List,
    Locksroot,
    Optional,
    SecretHash,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService


def channel_state_until_state_change(
    raiden: "RaidenService",
    canonical_identifier: CanonicalIdentifier,
    state_change_identifier: StateChangeID,
) -> NettingChannelState:  # pragma: no unittest
    """Go through WAL state changes until a certain balance hash is found."""
    assert raiden.wal, "Raiden has not been started yet"

    chain_state = restore_state(
        transition_function=node.state_transition,
        storage=raiden.wal.storage,
        state_change_identifier=state_change_identifier,
        node_address=raiden.address,
    )

    msg = "There is a state change, therefore the state must be different from None"
    assert chain_state is not None, msg
    assert isinstance(chain_state, ChainState), msg

    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=canonical_identifier
    )

    if channel_state is None:
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
    """Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    filters: List[Dict[str, Any]] = []
    filters.append(
        {
            "balance_proof.canonical_identifier.chain_identifier": str(
                canonical_identifier.chain_identifier
            ),
            "balance_proof.canonical_identifier.token_network_address": to_hex_address(
                canonical_identifier.token_network_address
            ),
            "balance_proof.canonical_identifier.channel_identifier": str(
                canonical_identifier.channel_identifier
            ),
            "balance_proof.balance_hash": to_hex(balance_hash),
            "balance_proof.sender": to_hex_address(sender),
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
    """Returns the state change which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    filters: List[Dict[str, Any]] = []
    filters.append(
        {
            "balance_proof.canonical_identifier.chain_identifier": str(
                canonical_identifier.chain_identifier
            ),
            "balance_proof.canonical_identifier.token_network_address": to_hex_address(
                canonical_identifier.token_network_address
            ),
            "balance_proof.canonical_identifier.channel_identifier": str(
                canonical_identifier.channel_identifier
            ),
            "balance_proof.locksroot": to_hex(locksroot),
            "balance_proof.sender": to_hex_address(sender),
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
    """Returns the event which contains the corresponding balance
    proof.

    Use this function to find a balance proof for a call to settle, which only
    has the blinded balance proof data.
    """
    filters: List[Dict[str, Any]] = []

    filter_items = {
        "canonical_identifier.chain_identifier": str(canonical_identifier.chain_identifier),
        "canonical_identifier.token_network_address": to_hex_address(
            canonical_identifier.token_network_address
        ),
        "canonical_identifier.channel_identifier": str(canonical_identifier.channel_identifier),
        "balance_hash": to_hex(balance_hash),
    }

    balance_proof_filters = balance_proof_query_from_keys(prefix="", filters=filter_items)
    balance_proof_filters["recipient"] = to_hex_address(recipient)
    filters.append(balance_proof_filters)

    transfer_filters = balance_proof_query_from_keys(prefix="transfer.", filters=filter_items)
    transfer_filters["recipient"] = to_hex_address(recipient)
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
    """Returns the event which contains the corresponding balance proof.

    Use this function to find a balance proof for a call to unlock, which only
    happens after settle, so the channel has the unblinded version of the
    balance proof.
    """
    filters: List[Dict[str, Any]] = []

    filter_items = {
        "canonical_identifier.chain_identifier": str(canonical_identifier.chain_identifier),
        "canonical_identifier.token_network_address": to_hex_address(
            canonical_identifier.token_network_address
        ),
        "canonical_identifier.channel_identifier": str(canonical_identifier.channel_identifier),
        "locksroot": to_hex(locksroot),
    }
    balance_proof_filters = balance_proof_query_from_keys(prefix="", filters=filter_items)
    balance_proof_filters["recipient"] = to_hex_address(recipient)
    filters.append(balance_proof_filters)

    transfer_filters = balance_proof_query_from_keys(prefix="transfer.", filters=filter_items)
    transfer_filters["recipient"] = to_hex_address(recipient)
    filters.append(transfer_filters)

    query = FilteredDBQuery(
        filters=filters, main_operator=Operator.OR, inner_operator=Operator.AND
    )
    event = storage.get_latest_event_by_data_field(query)
    return event


def get_state_change_with_transfer_by_secrethash(
    storage: SerializedSQLiteStorage, secrethash: SecretHash
) -> Optional[StateChangeRecord]:
    filters = [
        {"from_transfer.lock.secrethash": to_hex(secrethash)},
        {"transfer.lock.secrethash": to_hex(secrethash)},
    ]
    query = FilteredDBQuery(
        filters=filters, main_operator=Operator.OR, inner_operator=Operator.NONE
    )
    return storage.get_latest_state_change_by_data_field(query)


def balance_proof_query_from_keys(prefix: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    transformed_filters = {}
    for key, value in filters.items():
        transformed_filters[f"{prefix}balance_proof.{key}"] = value
    return transformed_filters
