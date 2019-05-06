import json
from typing import TYPE_CHECKING, TypeVar

from eth_utils import to_checksum_address

from raiden.storage.sqlite import SQLiteStorage
from raiden.utils.typing import Any, Callable, ChainID, Dict, List, Optional, Union

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService

SOURCE_VERSION = 21
TARGET_VERSION = 22
T = TypeVar("T")

BATCH_UNLOCK = "raiden.transfer.state_change.ContractReceiveChannelBatchUnlock"

SPELLING_VARS_TOKEN_NETWORK = (
    "token_network_address",
    "token_network_id",
    "token_network_identifier",
)

SPELLING_VARS_CHANNEL = ("channel_identifier", "channel_id", "identifier")

SPELLING_VARS_CHAIN = ("chain_id", "chain_identifier")


# these are missing the chain-id
by_adding_chain_id_then_contraction = {
    "raiden.transfer.state.TargetTask",
    "raiden.transfer.events.ContractSendChannelSettle",
    "raiden.transfer.state_change.ActionChannelClose",
    "raiden.transfer.state_change.ContractReceiveChannelClosed",
    "raiden.transfer.state_change.ContractReceiveChannelNewBalance",
    "raiden.transfer.state_change.ContractReceiveChannelSettled",
    "raiden.transfer.state_change.ContractReceiveRouteNew",
    "raiden.transfer.state_change.ContractReceiveRouteClosed",
    "raiden.transfer.state_change.ContractReceiveUpdateTransfer",
}


def pop_first_key(obj: Dict[str, T], keys: List[str]) -> T:
    return next(obj.pop(k) for k in keys if k in obj)


def _add_chain_id_then_contract(obj: Dict[str, Any], chain_id: ChainID) -> None:
    assert isinstance(obj, dict)
    assert obj["_type"] in by_adding_chain_id_then_contraction

    obj["canonical_identifier"] = {
        "chain_identifier": chain_id,
        "token_network_address": pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        "channel_identifier": pop_first_key(obj, SPELLING_VARS_CHANNEL),
    }


# these are missing chain-id and channel-id
by_adding_chain_id_channel_id_then_contraction = {BATCH_UNLOCK}


def _add_chain_id_channel_id_then_contract(
    obj: Dict[str, Any], chain_id: ChainID, channel_id: int
) -> None:
    assert isinstance(obj, dict)
    assert obj["_type"] in by_adding_chain_id_channel_id_then_contraction

    obj["canonical_identifier"] = {
        "chain_identifier": chain_id,
        "token_network_address": pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        "channel_identifier": channel_id,
    }


# these are missing the chain-id and have a superfluous token_address
by_adding_chain_id_removing_token_address = {
    "raiden.transfer.events.ContractSendChannelClose",
    "raiden.transfer.events.ContractSendChannelBatchUnlock",
}


def _remove_token_address_add_chain_id_then_contract(
    obj: Dict[str, Any], chain_id: ChainID
) -> None:
    assert isinstance(obj, dict)
    assert obj["_type"] in by_adding_chain_id_removing_token_address

    obj.pop("token_address")
    obj["canonical_identifier"] = {
        "chain_identifier": chain_id,
        "token_network_address": pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        "channel_identifier": pop_first_key(obj, SPELLING_VARS_CHANNEL),
    }


# these have all three fields already
by_contraction = {
    "raiden.transfer.state.BalanceProofUnsignedState",
    "raiden.transfer.state.BalanceProofSignedState",
    "raiden.transfer.state.NettingChannelState",
}


def _contract(obj: Dict[str, Any]) -> None:
    assert isinstance(obj, dict)
    assert obj["_type"] in by_contraction

    obj["canonical_identifier"] = {
        "chain_identifier": pop_first_key(obj, SPELLING_VARS_CHAIN),
        "token_network_address": pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        "channel_identifier": pop_first_key(obj, SPELLING_VARS_CHANNEL),
    }


# these are canonically-identified through sub-fields
by_removal_channel_id_token_network_identifier = {
    "raiden.transfer.events.ContractSendChannelUpdateTransfer"
}


def _remove_channel_id_token_network_identifier(obj) -> None:
    assert isinstance(obj, dict)
    assert obj["_type"] in by_removal_channel_id_token_network_identifier

    pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK)
    pop_first_key(obj, SPELLING_VARS_CHANNEL)


by_removal_token_network_identifier = {"raiden.transfer.state_change.ContractReceiveChannelNew"}


def _remove_token_network_identifier(obj) -> None:
    assert isinstance(obj, dict)
    assert obj["_type"] in by_removal_token_network_identifier

    pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK)


ALL_MIGRATING = by_contraction.union(
    by_adding_chain_id_removing_token_address,
    by_adding_chain_id_then_contraction,
    by_adding_chain_id_channel_id_then_contraction,
    by_removal_channel_id_token_network_identifier,
    by_removal_token_network_identifier,
)

ALL_REMOVE_MIGRATIONS = by_removal_channel_id_token_network_identifier.union(
    by_removal_token_network_identifier
)


def constraint_removed_duplicated_values(obj: Dict[str, Any]) -> None:
    if obj.get("_type") in ALL_REMOVE_MIGRATIONS:
        for key in SPELLING_VARS_CHANNEL:
            assert key not in obj
        for key in SPELLING_VARS_TOKEN_NETWORK:
            assert key not in obj


def contraint_has_canonical_identifier(obj: Dict[str, Any]) -> None:
    _type = obj.get("_type")
    if _type in ALL_MIGRATING and _type not in ALL_REMOVE_MIGRATIONS:
        canonical_identifier = obj.get("canonical_identifier")
        assert canonical_identifier is not None
        assert canonical_identifier["chain_identifier"] is not None
        assert canonical_identifier["token_network_address"] is not None
        assert canonical_identifier["channel_identifier"] is not None


def constraint_has_canonical_identifier_or_values_removed(obj: Dict[str, Any]) -> None:
    constraint_removed_duplicated_values(obj)
    contraint_has_canonical_identifier(obj)


def walk_dicts(obj: Union[List, Dict], callback: Callable) -> None:
    stack = [obj]

    while stack:
        obj = stack.pop()
        if isinstance(obj, dict):
            callback(obj)
            stack.extend(obj.values())
        elif isinstance(obj, list):
            stack.extend(obj)


def upgrade_object(obj: Dict[str, Any], chain_id: ChainID, channel_id: int = None) -> None:
    _type = obj.get("_type")

    if _type in by_contraction:
        _contract(obj)
    elif _type in by_removal_token_network_identifier:
        _remove_token_network_identifier(obj)
    elif _type in by_removal_channel_id_token_network_identifier:
        _remove_channel_id_token_network_identifier(obj)
    elif _type in by_adding_chain_id_removing_token_address:
        _remove_token_address_add_chain_id_then_contract(obj, chain_id)
    elif _type in by_adding_chain_id_then_contraction:
        _add_chain_id_then_contract(obj, chain_id)
    elif _type in by_adding_chain_id_channel_id_then_contraction:
        assert channel_id is not None
        _add_chain_id_channel_id_then_contract(obj, chain_id, channel_id)
    elif _type in ALL_MIGRATING:
        assert False


def _add_canonical_identifier_to_snapshot(storage: SQLiteStorage, chain_id: ChainID) -> None:
    updated_snapshots_data = []

    for snapshot_record in storage.get_snapshots():
        snapshot_obj = json.loads(snapshot_record.data)

        walk_dicts(snapshot_obj, lambda obj: upgrade_object(obj, chain_id))
        walk_dicts(snapshot_obj, constraint_has_canonical_identifier_or_values_removed)
        updated_snapshots_data.append((json.dumps(snapshot_obj), snapshot_record.identifier))

    storage.update_snapshots(updated_snapshots_data)


def _add_canonical_identifier_to_statechanges(
    raiden: "RaidenService", storage: SQLiteStorage, chain_id: ChainID
) -> None:
    our_address = str(to_checksum_address(raiden.address)).lower()

    for state_change_batch in storage.batch_query_state_changes(batch_size=500):
        updated_state_changes = list()
        delete_state_changes = list()

        for state_change_record in state_change_batch:
            state_change_obj = json.loads(state_change_record.data)
            is_unlock = state_change_obj["_type"] == BATCH_UNLOCK
            should_delete = is_unlock and our_address not in (  # Delete unecessary unlock events
                state_change_obj["partner"].lower(),
                state_change_obj["participant"].lower(),
            )

            if should_delete:
                delete_state_changes.append(state_change_record.identifier)
            else:
                channel_id = None
                if is_unlock:
                    channel_id = resolve_channel_id_for_unlock(
                        storage, state_change_obj, our_address
                    )
                walk_dicts(
                    state_change_obj,
                    lambda obj, channel_id=channel_id: upgrade_object(obj, chain_id, channel_id),
                )

            walk_dicts(state_change_obj, constraint_has_canonical_identifier_or_values_removed)
            updated_state_changes.append(
                (json.dumps(state_change_obj), state_change_record.state_change_identifier)
            )

        storage.update_state_changes(updated_state_changes)
        storage.delete_state_changes(delete_state_changes)


def resolve_channel_id_for_unlock(
    storage: SQLiteStorage, obj: Dict[str, Any], our_address: str
) -> Optional[int]:
    assert obj["_type"] == BATCH_UNLOCK

    locksroot = obj["locksroot"]
    _participant = obj["participant"]
    _partner = obj["partner"]
    partner_address = _partner if _participant.lower() == our_address.lower() else _participant
    # 1) query state_changes for ....BalanceProofSignedState with match
    # 2) query events for BalanceProofUnsignedState with match
    receiving = storage.get_latest_state_change_by_data_field(
        filters={"balance_proof.locksroot": locksroot, "balance_proof.sender": partner_address}
    )
    if receiving.data is not None:
        receiving_data = json.loads(receiving.data)
        if receiving_data["balance_proof"]["sender"] == partner_address:
            balance_proof = receiving_data["balance_proof"]
            if "canonical_identifier" in balance_proof:
                return balance_proof["canonical_identifier"]["channel_identifier"]
            elif "channel_identifier" in balance_proof:
                return balance_proof["channel_identifier"]

    sending = storage.get_latest_event_by_data_field(
        filters={
            "balance_proof.locksroot": locksroot,
            "balance_proof._type": "raiden.transfer.state.BalanceProofUnsignedState",
            "recipient": partner_address,
        }
    )
    if sending.data is not None:
        sending_data = json.loads(sending.data)
        balance_proof = sending_data["balance_proof"]
        if "canonical_identifier" in balance_proof:
            return balance_proof["canonical_identifier"]["channel_identifier"]
        elif "channel_identifier" in balance_proof:
            return balance_proof["channel_identifier"]
    return None


def _add_canonical_identifier_to_events(storage: SQLiteStorage, chain_id: ChainID) -> None:
    for events_batch in storage.batch_query_event_records(batch_size=500):
        updated_events = []
        for event_record in events_batch:
            event_obj = json.loads(event_record.data)
            walk_dicts(event_obj, lambda obj: upgrade_object(obj, chain_id))
            walk_dicts(event_obj, constraint_has_canonical_identifier_or_values_removed)
            updated_events.append((json.dumps(event_obj), event_record.event_identifier))
        storage.update_events(updated_events)


def recover_chain_id(storage: SQLiteStorage) -> ChainID:
    """We can reasonably assume, that any database has only one value for `chain_id` at this point
    in time.
    """
    action_init_chain = json.loads(storage.get_state_changes(limit=1, offset=0)[0])

    assert action_init_chain["_type"] == "raiden.transfer.state_change.ActionInitChain"
    return action_init_chain["chain_id"]


def upgrade_v21_to_v22(
    storage: SQLiteStorage,
    old_version: int,
    current_version: int,
    raiden: "RaidenService",
    **kwargs,  # pylint: disable=unused-argument
) -> int:
    assert current_version == TARGET_VERSION
    if old_version == SOURCE_VERSION:
        chain_id = recover_chain_id(storage)
        _add_canonical_identifier_to_snapshot(storage, chain_id)
        _add_canonical_identifier_to_events(storage, chain_id)
        _add_canonical_identifier_to_statechanges(raiden, storage, chain_id)

    return TARGET_VERSION
