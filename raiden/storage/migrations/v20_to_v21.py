import json

from raiden.storage.sqlite import SQLiteStorage

SOURCE_VERSION = 20
TARGET_VERSION = 21


def _transform_snapshot(raw_snapshot: str) -> str:
    snapshot = json.loads(raw_snapshot)

    for task in snapshot['payment_mapping']['secrethashes_to_task'].values():
        if 'raiden.transfer.state.InitiatorTask' in task['_type']:
            for initiator in task['manager_task']['initiator_transfers'].values():
                initiator['transfer_description']['allocated_fee'] = 0

    ids_to_addrs = dict()
    for payment_network in snapshot['identifiers_to_paymentnetworks'].values():
        for token_network in payment_network['tokenidentifiers_to_tokennetworks'].values():
            ids_to_addrs[payment_network['address']] = token_network['token_address']
    snapshot['tokennetworkaddresses_to_paymentnetworkaddresses'] = ids_to_addrs

    for payment_network in snapshot['identifiers_to_paymentnetworks'].values():
        for token_network in payment_network['tokenidentifiers_to_tokennetworks'].values():
            for channel_state in token_network['channelidentifiers_to_channels'].values():
                channel_state['mediation_fee'] = 0

    return json.dumps(snapshot)


def _update_snapshots(storage: SQLiteStorage):
    updated_snapshots_data = []
    for snapshot in storage.get_snapshots():
        new_snapshot = _transform_snapshot(snapshot.data)
        updated_snapshots_data.append((new_snapshot, snapshot.identifier))

    storage.update_snapshots(updated_snapshots_data)


def _update_statechanges(storage: SQLiteStorage):
    batch_size = 50
    batch_query = storage.batch_query_state_changes(
        batch_size=batch_size,
        filters=[
            ('_type', 'raiden.transfer.state_change.ContractReceiveChannelNew'),
        ],
    )

    for state_changes_batch in batch_query:
        for state_change in state_changes_batch:
            state_change['channel_state']['mediation_fee'] = 0
        storage.update_state_changes(state_changes_batch)

    batch_query = storage.batch_query_state_changes(
        batch_size=batch_size,
        filters=[
            ('_type', 'raiden.transfer.mediated_transfer.state_change.ActionInitInitiator'),
        ],
    )

    for state_changes_batch in batch_query:
        for state_change in state_changes_batch:
            state_change['transfer']['allocated_fee'] = 0
        storage.update_state_changes(state_changes_batch)


def upgrade_v19_to_v20(
        storage: SQLiteStorage,
        old_version: int,
        **kwargs,  # pylint: disable=unused-argument
) -> int:
    if old_version == SOURCE_VERSION:
        _update_snapshots(storage)
        _update_statechanges(storage)

    return TARGET_VERSION
