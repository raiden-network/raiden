import structlog

from raiden.transfer.architecture import StateManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def restore_from_latest_snapshot(transition_function, storage):
    snapshot = storage.get_latest_state_snapshot()

    if snapshot:
        log.debug('Restoring from snapshot')
        last_applied_state_change_id, state = snapshot
        unapplied_state_changes = storage.get_statechanges_by_identifier(
            from_identifier=last_applied_state_change_id,
            to_identifier='latest',
        )
    else:
        log.debug('No snapshot found, replaying all state changes')
        state = None
        unapplied_state_changes = storage.get_statechanges_by_identifier(
            from_identifier=0,
            to_identifier='latest',
        )

    state_manager = StateManager(transition_function, state)
    wal = WriteAheadLog(state_manager, storage)

    log.debug('Replaying state changes', num_state_changes=len(unapplied_state_changes))
    for state_change in unapplied_state_changes:
        state_manager.dispatch(state_change)

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

        events = self.state_manager.dispatch(state_change)

        self.state_change_id = state_change_id
        self.storage.write_events(state_change_id, events)

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
