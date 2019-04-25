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
T = TypeVar('T')

SPELLING_VARS_TOKEN_NETWORK = (
    'token_network_address',
    'token_network_id',
    'token_network_identifier',
)

SPELLING_VARS_CHANNEL = (
    'channel_identifier',
    'channel_id',
    'identifier',
)

SPELLING_VARS_CHAIN = (
    'chain_id',
    'chain_identifier',
)


# these are missing the chain-id
by_adding_chain_id_then_contraction = {
    'raiden.transfer.state.TargetTask',
    'raiden.transfer.events.ContractSendChannelSettle',
    'raiden.transfer.state_change.ActionChannelClose',
    'raiden.transfer.state_change.ContractReceiveChannelClosed',
    'raiden.transfer.state_change.ContractReceiveChannelNewBalance',
    'raiden.transfer.state_change.ContractReceiveChannelSettled',
    'raiden.transfer.state_change.ContractReceiveRouteNew',
    'raiden.transfer.state_change.ContractReceiveRouteClosed',
    'raiden.transfer.state_change.ContractReceiveUpdateTransfer',
}


def pop_first_key(obj: Dict[str, T], keys: List[str]) -> T:
    return next(obj.pop(k) for k in keys if k in obj)


def _add_chain_id_then_contract(obj: Dict[str, Any], chain_id: ChainID) -> None:
    assert isinstance(obj, dict)
    assert obj['_type'] in by_adding_chain_id_then_contraction

    obj['canonical_identifier'] = {
        'chain_identifier': chain_id,
        'token_network_address': pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        'channel_identifier': pop_first_key(obj, SPELLING_VARS_CHANNEL),
    }


# these are missing chain-id and channel-id
by_adding_chain_id_channel_id_then_contraction = {
    'raiden.transfer.state_change.ContractReceiveChannelBatchUnlock',
}


def _add_chain_id_channel_id_then_contract(
        obj: Dict[str, Any],
        chain_id: ChainID,
        channel_id: int,
) -> None:
    assert isinstance(obj, dict)
    assert obj['_type'] in by_adding_chain_id_channel_id_then_contraction

    obj['canonical_identifier'] = {
        'chain_identifier': chain_id,
        'token_network_address': pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        'channel_identifier': channel_id,
    }


# these are missing the chain-id and have a superfluous token_address
by_adding_chain_id_removing_token_address = {
    'raiden.transfer.events.ContractSendChannelClose',
    'raiden.transfer.events.ContractSendChannelBatchUnlock',
}


def _remove_token_address_add_chain_id_then_contract(
        obj: Dict[str, Any],
        chain_id: ChainID,
) -> None:
    assert isinstance(obj, dict)
    assert obj['_type'] in by_adding_chain_id_removing_token_address

    obj.pop('token_address')
    obj['canonical_identifier'] = {
        'chain_identifier': chain_id,
        'token_network_address': pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        'channel_identifier': pop_first_key(obj, SPELLING_VARS_CHANNEL),
    }


# these have all three fields already
by_contraction = {
    'raiden.transfer.state.BalanceProofUnsignedState',
    'raiden.transfer.state.BalanceProofSignedState',
    'raiden.transfer.state.NettingChannelState',
}


def _contract(obj: Dict[str, Any]) -> None:
    assert isinstance(obj, dict)
    assert obj['_type'] in by_contraction

    obj['canonical_identifier'] = {
        'chain_identifier': pop_first_key(obj, SPELLING_VARS_CHAIN),
        'token_network_address': pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK),
        'channel_identifier': pop_first_key(obj, SPELLING_VARS_CHANNEL),
    }


# these are canonically-identified through sub-fields
by_removal_channel_id_token_network_identifier = {
    'raiden.transfer.events.ContractSendChannelUpdateTransfer',
}


def _remove_channel_id_token_network_identifier(obj) -> None:
    assert isinstance(obj, dict)
    assert obj['_type'] in by_removal_channel_id_token_network_identifier

    pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK)
    pop_first_key(obj, SPELLING_VARS_CHANNEL)


by_removal_token_network_identifier = {
    'raiden.transfer.state_change.ContractReceiveChannelNew',
}


def _remove_token_network_identifier(obj) -> None:
    assert isinstance(obj, dict)
    assert obj['_type'] in by_removal_token_network_identifier

    pop_first_key(obj, SPELLING_VARS_TOKEN_NETWORK)


ALL_MIGRATING = by_contraction.union(
    by_adding_chain_id_removing_token_address,
    by_adding_chain_id_then_contraction,
    by_adding_chain_id_channel_id_then_contraction,
    by_removal_channel_id_token_network_identifier,
    by_removal_token_network_identifier,
)

ALL_REMOVE_MIGRATIONS = by_removal_channel_id_token_network_identifier.union(
    by_removal_token_network_identifier,
)


def constraint_removed_duplicated_values(obj: Dict[str, Any]) -> None:
    if obj['_type'] in ALL_REMOVE_MIGRATIONS:
        for key in SPELLING_VARS_CHANNEL:
            assert key not in obj
        for key in SPELLING_VARS_TOKEN_NETWORK:
            assert key not in obj


def contraint_has_canonical_identifier(obj: Dict[str, Any], keys: List[str]) -> None:
    if obj['_type'] not in ALL_REMOVE_MIGRATIONS:
        canonical_identifier = obj.get('canonical_identifier')
        assert canonical_identifier is not None, (keys, obj)
        assert canonical_identifier['chain_identifier'] is not None, (keys, obj)
        assert canonical_identifier['token_network_address'] is not None, (keys, obj)
        assert canonical_identifier['channel_identifier'] is not None, (keys, obj)


def constraint_has_canonical_identifier_or_values_removed(
        obj: Dict[str, Any],
        keys: List[str],
) -> None:
    constraint_removed_duplicated_values(obj)
    contraint_has_canonical_identifier(obj, keys)


def check_constraint(obj: Dict[str, Any], constraint: Callable) -> None:
    for _type, data, keys in scanner(obj):
        constraint(data, keys)


def scanner(obj: Union[List, Dict[str, Any], int, str], keys: List[str] = None) -> Any:
    if keys is None:
        keys = []
    if isinstance(obj, dict):
        if obj.get('_type') in ALL_MIGRATING:
            yield (obj.get('_type'), obj, keys)
        for key, value in obj.items():
            yield from scanner(value, keys=keys + [key])
    elif isinstance(obj, list):
        for num, item in enumerate(obj):
            yield from scanner(item, keys=keys + [f'[{num}]'])
    else:
        if obj is not None:
            assert isinstance(obj, (int, str))


def upgrade_object(
        obj: Dict[str, Any],
        chain_id: ChainID,
        channel_id: int = None,
) -> None:
    if obj is None:
        return

    _type = obj['_type']

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

    return


def snapshot_upgrade_pending_transactions(
        snapshot: Dict[str, Any],
        chain_id: ChainID,
) -> None:
    for tx in snapshot['pending_transactions']:
        upgrade_object(tx, chain_id)
        if isinstance(tx, dict) and 'balance_proof' in tx:
            upgrade_object(tx['balance_proof'], chain_id)


def snapshot_upgrade_queues(
        snapshot: Dict[str, Any],
        chain_id: ChainID,
) -> None:
    for _id, data in snapshot['queueids_to_queues'].values():
        for item in data:
            if isinstance(item, dict) and 'balance_proof' in item:
                upgrade_object(item['balance_proof'], chain_id)
            if isinstance(item, dict) and 'transfer' in item:
                if isinstance(item['transfer'], dict) and 'balance_proof' in item['transfer']:
                    upgrade_object(item['transfer']['balance_proof'], chain_id)


def snapshot_upgrade_channels(
        snapshot: Dict[str, Any],
        chain_id: ChainID,
) -> None:
    for network in snapshot['identifiers_to_paymentnetworks'].values():
        for token_network in network['tokennetworks']:
            for channel in token_network['channelidentifiers_to_channels'].values():
                upgrade_object(channel, chain_id)
                if (
                        'our_state' in channel and
                        isinstance(channel['our_state'], dict) and
                        'balance_proof' in channel['our_state']
                ):
                    upgrade_object(channel['our_state']['balance_proof'], chain_id)
                if (
                        'partner_state' in channel and
                        isinstance(channel['partner_state'], dict) and
                        'balance_proof' in channel['partner_state']
                ):
                    upgrade_object(channel['partner_state']['balance_proof'], chain_id)


def snapshot_upgrade_payment_mappings(
        snapshot: Dict[str, Any],
        chain_id: ChainID,
) -> None:
    for task in snapshot['payment_mapping']['secrethashes_to_task'].values():
        upgrade_object(task, chain_id)
        if isinstance(task, dict) and 'manager_state' in task:
            if (
                    isinstance(task['manager_state'], dict) and
                    'initiator_transfers' in task['manager_state']
            ):
                for transfer in task['manager_state']['initiator_transfers'].values():
                    if (
                            isinstance(transfer, dict) and
                            'transfer' in transfer and
                            isinstance(transfer['transfer'], dict) and
                            'balance_proof' in transfer['transfer']
                    ):
                        upgrade_object(transfer['transfer']['balance_proof'], chain_id)
        if (
                isinstance(task, dict) and
                'mediator_state' in task and
                isinstance(task['mediator_state'], dict) and
                'transfers_pair' in task['mediator_state']
        ):
            for transfer in task['mediator_state']['transfers_pair']:
                if (
                        isinstance(transfer, dict) and
                        'payer_transfer' in transfer and
                        isinstance(transfer['payer_transfer'], dict) and
                        'balance_proof' in transfer['payer_transfer']
                ):
                    upgrade_object(transfer['payer_transfer']['balance_proof'], chain_id)
                if (
                        isinstance(transfer, dict) and
                        'payee_transfer' in transfer and
                        isinstance(transfer['payee_transfer'], dict) and
                        'balance_proof' in transfer['payee_transfer']
                ):
                    upgrade_object(transfer['payee_transfer']['balance_proof'], chain_id)
        if (
                isinstance(task, dict) and
                'target_state' in task and
                isinstance(task['target_state'], dict) and
                'transfer' in task['target_state'] and
                isinstance(task['target_state']['transfer'], dict) and
                'balance_proof' in task['target_state']['transfer']
        ):
            upgrade_object(task['target_state']['transfer']['balance_proof'], chain_id)


def _add_canonical_identifier_to_snapshot(
        raiden: 'RaidenService',
        storage: SQLiteStorage,
) -> None:
    assert raiden

    updated_snapshots_data = []

    for snapshot_record in storage.get_snapshots():
        snapshot = json.loads(snapshot_record.data)
        assert isinstance(snapshot, (dict, list))

        chain_id = snapshot['chain_id']

        snapshot_upgrade_pending_transactions(snapshot, chain_id)
        snapshot_upgrade_channels(snapshot, chain_id)
        snapshot_upgrade_queues(snapshot, chain_id)
        snapshot_upgrade_payment_mappings(snapshot, chain_id)
        check_constraint(
            snapshot,
            constraint=constraint_has_canonical_identifier_or_values_removed,
        )
        updated_snapshots_data.append((snapshot, snapshot.identifier))

    storage.update_snapshots(updated_snapshots_data)


def _add_canonical_identifier_to_statechanges(
        raiden: 'RaidenService',
        storage: SQLiteStorage,
        chain_id: ChainID,
) -> None:
    assert raiden
    assert chain_id is not None

    our_address = to_checksum_address(raiden.address)

    for state_change_batch in storage.batch_query_state_changes(batch_size=500):
        updated_state_changes = list()

        for state_change in state_change_batch:
            state_change_obj = json.loads(state_change.data)
            for _type, obj, _path in scanner(state_change_obj):
                if (
                        obj['_type'] ==
                        'raiden.transfer.state_change.ContractReceiveChannelBatchUnlock'
                ):
                    if our_address.lower() not in (
                            obj['partner'].lower(),
                            obj['participant'].lower(),
                    ):
                        # delete it, we're not part of it
                        assert obj == state_change_obj
                        del obj
                        del state_change_obj
                        state_change_obj = None
                        conn = storage.conn.cursor()
                        conn.execute(
                            'DELETE from state_changes WHERE identifier = ?',
                            state_change.state_change_identifier,
                        )
                        conn.commit()
                        conn.close()
                    else:
                        channel_id = resolve_channel_id_for_unlock(
                            storage,
                            obj,
                            our_address,
                        )

                        assert channel_id is not None
                        if channel_id is not None:
                            upgrade_object(obj, chain_id, channel_id=channel_id)
                else:
                    upgrade_object(obj, chain_id)

            check_constraint(
                state_change_obj,
                constraint=constraint_has_canonical_identifier_or_values_removed,
            )
            updated_state_changes.append((
                json.dumps(state_change[1]),
                state_change.state_change_identifier,
            ))

        storage.update_state_changes(updated_state_changes)


def resolve_channel_id_for_unlock(
        storage: SQLiteStorage,
        obj: Dict[str, Any],
        our_address: str,
) -> Optional[int]:

    assert obj['_type'] == 'raiden.transfer.state_change.ContractReceiveChannelBatchUnlock'

    locksroot = obj['locksroot']
    _participant = obj['participant']
    _partner = obj['partner']
    partner_address = (
        _partner if _participant.lower() == our_address.lower()
        else _participant
    )
    # 1) query state_changes for ....BalanceProofSignedState with match
    # 2) query events for BalanceProofUnsignedState with match
    receiving = storage.get_latest_state_change_by_data_field(
        filters={
            'balance_proof.locksroot': locksroot,
            'balance_proof.sender': partner_address,
        },
    )
    if receiving.data is not None:
        receiving_data = json.loads(receiving.data)
        if receiving_data['balance_proof']['sender'] == partner_address:
            balance_proof = receiving_data['balance_proof']
            if 'canonical_identifier' in balance_proof:
                return balance_proof['canonical_identifier']['channel_identifier']
            elif 'channel_identifier' in balance_proof:
                return balance_proof['channel_identifier']

    sending = storage.get_latest_event_by_data_field(
        filters={
            'balance_proof.locksroot': locksroot,
            'balance_proof._type': 'raiden.transfer.state.BalanceProofUnsignedState',
            'recipient': partner_address,
        },
    )
    if sending.data is not None:
        sending_data = json.loads(sending.data)
        balance_proof = sending_data['balance_proof']
        if 'canonical_identifier' in balance_proof:
            return balance_proof['canonical_identifier']['channel_identifier']
        elif 'channel_identifier' in balance_proof:
            return balance_proof['channel_identifier']
    raise RuntimeError('channel identifier could not be found during migration.')


def _add_canonical_identifier_to_events(
        raiden: 'RaidenService',
        storage: SQLiteStorage,
        chain_id: ChainID,
) -> None:
    assert raiden
    assert chain_id is not None
    for events_batch in storage.batch_query_event_records(batch_size=500):
        updated_events = []
        for event in events_batch:
            event_obj = json.loads(event.data)
            for _type, obj, _path in scanner(event_obj):
                upgrade_object(obj, chain_id)
            check_constraint(
                event_obj,
                constraint=constraint_has_canonical_identifier_or_values_removed,
            )
            updated_events.append((
                json.dumps(event_obj),
                event.event_identifier,
            ))
        storage.update_events(updated_events)


def recover_chain_id(storage: SQLiteStorage) -> ChainID:
    """We can reasonably assume, that any database has only one value for `chain_id` at this point
    in time.
    """
    action_init_chain = json.loads(storage.get_state_changes(limit=1, offset=0)[0])

    assert action_init_chain['_type'] == 'raiden.transfer.state_change.ActionInitChain'
    return action_init_chain['chain_id']


def upgrade_v21_to_v22(
        storage: SQLiteStorage,
        old_version: int,
        current_version: int,
        raiden: 'RaidenService',
        **kwargs,
) -> int:
    assert current_version == TARGET_VERSION
    assert not len(kwargs)
    if old_version == SOURCE_VERSION:
        chain_id = recover_chain_id(storage)
        _add_canonical_identifier_to_snapshot(raiden, storage)
        _add_canonical_identifier_to_events(raiden, storage, chain_id)
        _add_canonical_identifier_to_statechanges(raiden, storage, chain_id)

    return TARGET_VERSION
