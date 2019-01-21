import json

from raiden.storage.sqlite import SQLiteStorage


def _transform_snapshot(raw_snapshot):
    snapshot = json.loads(raw_snapshot)
    secrethash_to_task = snapshot['payment_mapping']['secrethashes_to_task']
    for secrethash, task in secrethash_to_task.items():
        if task['_type'] != 'raiden.transfer.state.InitiatorTask':
            continue

        # The transfer is pending as long as the initiator task still exists
        transfer_secrethash = task['manager_state']['initiator']['transfer']['lock']['secrethash']
        task['manager_state']['initiator']['transfer_state'] = 'transfer_pending'
        task['manager_state']['initiator_transfers'] = {
            transfer_secrethash: task['manager_state']['initiator'],
        }
        del task['manager_state']['initiator']
        secrethash_to_task[secrethash] = task
    return json.dumps(snapshot, indent=4)


def _transform_snapshots(storage):
    for identifier, snapshot in storage.get_snapshots(raw=True):
        new_snapshot = _transform_snapshot(snapshot)
        storage.update_snapshot(identifier, new_snapshot)


def upgrade_initiator_manager(storage: SQLiteStorage, old_version, current_version):
    """ InitiatorPaymentState was changed so that the "initiator"
    attribute is renamed to "initiator_transfers" and converted to a list.
    """
    if current_version > 16 and old_version == 16:
        _transform_snapshots(storage)
