import json

from raiden.storage.sqlite import SQLiteStorage
from raiden.utils.serialization import serialize_bytes

SOURCE_VERSION = 19
TARGET_VERSION = 20


def _add_onchain_locksroot_to_channel_settled_state_changes(
        storage: SQLiteStorage,
) -> None:
    """ Adds `our_onchain_locksroot` and `partner_onchain_locksroot` to
    ContractReceiveChannelSettled. """
    batch_size = 50
    batch_query = storage.batch_query_state_changes(
        batch_size=batch_size,
        filters=[
            ('_type', 'raiden.transfer.state_change.ContractReceiveChannelSettled'),
        ],
    )
    for state_changes_batch in batch_query:
        updated_state_changes = []
        for state_change in state_changes_batch:
            data = json.loads(state_change.data)
            msg = 'v18 state changes cant contain our_onchain_locksroot'
            assert 'our_onchain_locksroot' not in data, msg

            msg = 'v18 state changes cant contain partner_onchain_locksroot'
            assert 'partner_onchain_locksroot' not in data, msg

            data['our_onchain_locksroot'] = serialize_bytes(bytes(32))
            data['partner_onchain_locksroot'] = serialize_bytes(bytes(32))
            updated_state_changes.append((
                json.dumps(data),
                state_change.state_change_identifier,
            ))
        storage.update_state_changes(updated_state_changes)


def _add_partner_to_batch_unlock_events(storage: SQLiteStorage) -> None:
    """Adds partner to all ContractSendXXX events"""
    batch_query = storage.batch_query_event_records(
        batch_size=500,
        filters=[('_type', 'raiden.transfer.events.ContractSendChannelBatchUnlock')],
    )
    for events_batch in batch_query:
        updated_events = []
        for event in events_batch:
            data = json.loads(event.data)
            assert 'partner' not in data, 'v19 ContractSendChannelBatchUnlock contain partner'

            data['partner'] = 'something'

            updated_events.append((
                json.dumps(data),
                event.event_identifier,
            ))

        storage.update_events(updated_events)


def _add_onchain_locksroot_to_snapshot(raw_snapshot):
    """
    Add `onchain_locksroot` to each NettingChannelEndState
    """
    snapshot = json.loads(raw_snapshot)

    for payment_network in snapshot.get('identifiers_to_paymentnetworks', {}).values():
        for token_network in payment_network.get('tokennetworks', []):
            for channel in token_network.get('channelidentifiers_to_channels', []).values():
                channel['our_state']['onchain_locksroot'] = serialize_bytes(bytes(32))
                channel['partner_state']['onchain_locksroot'] = serialize_bytes(bytes(32))

    return json.dumps(snapshot, indent=4)


def _add_onchain_locksroot_to_snapshots(storage: SQLiteStorage):
    updated_snapshots_data = []
    for snapshot in storage.get_snapshots():
        new_snapshot = _add_onchain_locksroot_to_snapshot(snapshot.data)
        updated_snapshots_data.append((new_snapshot, snapshot.identifier))

    storage.update_snapshots(updated_snapshots_data)


def upgrade_v19_to_v20(
        storage: SQLiteStorage,
        old_version: int,
        current_version: int,
        **kwargs,
) -> int:
    if old_version == SOURCE_VERSION:
        _add_onchain_locksroot_to_channel_settled_state_changes(storage)
        _add_onchain_locksroot_to_snapshots(storage)
        _add_partner_to_batch_unlock_events(storage)

    return TARGET_VERSION
