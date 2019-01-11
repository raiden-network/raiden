from raiden.exceptions import InvalidDBData
from raiden.storage.restore import rebuild_chain_state
from raiden.storage.sqlite import SQLiteStorage


def _get_latest_state_change(storage: SQLiteStorage):
    cursor = storage.conn.cursor()
    sql = (
        f'SELECT identifier '
        f'FROM state_changes '
        f'ORDER BY identifier '
        f'DESC LIMIT 1'
    )
    cursor.execute(sql)
    try:
        row = cursor.fetchone()
        if not row:
            return 0
        return row[0]
    except AttributeError:
        raise InvalidDBData(
            'Your local database is corrupt. Bailing ...',
        )


def _remove_snapshots(storage: SQLiteStorage):
    storage.remove_snapshots()


def _create_snapshot(storage: SQLiteStorage):
    snapshot = rebuild_chain_state(storage)
    last_state_change_id = _get_latest_state_change(storage)

    if not last_state_change_id:
        # Databse does not have any records, no need for a snapshot
        return

    storage.write_state_snapshot(
        statechange_id=last_state_change_id,
        snapshot=snapshot,
    )


def upgrade(storage: SQLiteStorage):
    """ InitiatorPaymentState was changed so that the "initiator"
    attribute is renamed to "initiator_transfers" and converted to a list.
    Since the change exists in a "state" rather than a "state_change" or an "event",
    then the migration strategy would be to prevent loading a snapshot in which
    the attribute "initiator" is still used. Therefore, this migration deletes
    all existing snapshots, rebuilds the state and then creates a new snapshot
    with the new attribute in place."""
    _remove_snapshots(storage)
    _create_snapshot(storage)
