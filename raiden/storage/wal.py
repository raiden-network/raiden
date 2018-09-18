from datetime import datetime

import structlog

from raiden.transfer.architecture import StateManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def restore_to_state_change(transition_function, storage, state_change_identifier):
    snapshot = storage.get_snapshot_closest_to_state_change(state_change_identifier)

    from_state_change_id = 0
    chain_state = None
    if snapshot:
        log.debug('Restoring from snapshot')
        from_state_change_id, chain_state = snapshot
    else:
        log.debug('No snapshot found, replaying all state changes')

    unapplied_state_changes = storage.get_statechanges_by_identifier(
        from_identifier=from_state_change_id,
        to_identifier=state_change_identifier,
    )

    state_manager = StateManager(transition_function, chain_state)
    wal = WriteAheadLog(state_manager, storage)

    log.debug('Replaying state changes', num_state_changes=len(unapplied_state_changes))
    for state_change in unapplied_state_changes:
        wal.state_manager.dispatch(state_change)

    return wal


class WriteAheadLog:
    def __init__(self, state_manager, storage):
        self.state_manager = state_manager
        self.state_change_id = None
        self.storage = storage

    def log_and_dispatch(self, state_change):
        """ Log and apply a state change.

        This function will first write the state change to the write-ahead-log,
        in case of a node crash the state change can be recovered and replayed
        to restore the node state.

        Events produced by applying state change are also saved.
        """
        state_change_id = self.storage.write_state_change(state_change)
        self.state_change_id = state_change_id

        events = self.state_manager.dispatch(state_change)

        timestamp = datetime.utcnow().isoformat(timespec='milliseconds')
        self.storage.write_events(state_change_id, events, timestamp)

        return events

    def snapshot(self):
        """ Snapshot the application state.

        Snapshots are used to restore the application state, either after a
        restart or a crash.
        """
        current_state = self.state_manager.current_state
        state_change_id = self.state_change_id

        # otherwise no state change was dispatched
        if state_change_id:
            self.storage.write_state_snapshot(state_change_id, current_state)

    @property
    def version(self):
        return self.storage.get_version()
