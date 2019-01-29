import json
import sqlite3


def get_snapshots(cursor):
    cursor.execute('SELECT identifier, data FROM state_snapshot')
    snapshots = cursor.fetchall()
    for snapshot in snapshots:
        yield snapshot[0], snapshot[1]


def update_snapshot(cursor, identifier, new_snapshot):
    cursor.execute(
        'UPDATE state_snapshot SET data=? WHERE identifier=?',
        (new_snapshot, identifier),
    )


def _transform_snapshot(raw_snapshot):
    """
    Version 16 data model:
    - The top-level is always a `ChainState` object, this object will always
      have a `PaymentMappingState`, the attribute `secrethashes_to_task` is a
      dictionary that may be empty.
    - `secrethashes_to_task` may have `InitiatorTask`s in it, these objects always
      have a `manager_state: InitiatorPaymentState`,which always have
      `initiator: InitiatorTransferState`

    This migration upgrades the objects:

    - `InitiatorPaymentState`, that may be contained in `secrethashes_to_task`.
      In version 16 these objects had a single `initiator` object,
      where in version 17 this was changed to a `Dict[SecretHash, 'InitiatorTransferState']`
    - `InitiatorTransferState` has a new attribute `transfer_state`
    """
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


def _transform_snapshots(cursor: sqlite3.Cursor):
    for identifier, snapshot in get_snapshots(cursor):
        new_snapshot = _transform_snapshot(snapshot)
        update_snapshot(cursor, identifier, new_snapshot)


def upgrade_initiator_manager(cursor: sqlite3.Cursor, old_version: int, current_version: int):
    """ InitiatorPaymentState was changed so that the "initiator"
    attribute is renamed to "initiator_transfers" and converted to a list.
    """
    if current_version > 16 and old_version == 16:
        _transform_snapshots(cursor)
