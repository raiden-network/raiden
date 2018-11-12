from datetime import datetime

import gevent.lock
import structlog

from raiden.storage.sqlite import SQLiteStorage
from raiden.transfer.architecture import StateManager
from raiden.utils import typing

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def restore_to_state_change(
        transition_function: typing.Callable,
        storage: SQLiteStorage,
        state_change_identifier: int,
) -> 'WriteAheadLog':
    msg = "state change identifier 'latest' or an integer greater than zero"
    assert state_change_identifier == 'latest' or state_change_identifier > 0, msg

    from_state_change_id, chain_state = storage.get_snapshot_closest_to_state_change(
        state_change_identifier=state_change_identifier,
    )

    if chain_state is not None:
        log.debug(
            'Restoring from snapshot',
            from_state_change_id=from_state_change_id,
            to_state_change_id=state_change_identifier,
        )
    else:
        log.debug(
            'No snapshot found, replaying all state changes',
            to_state_change_id=state_change_identifier,
        )

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

        # The state changes must be applied in the same order as they are saved
        # to the WAL. Because writing to the database context switches, and the
        # scheduling is undetermined, a lock is necessary to protect the
        # execution order.
        self._lock = gevent.lock.Semaphore()

    def log_and_dispatch(self, state_change):
        """ Log and apply a state change.

        This function will first write the state change to the write-ahead-log,
        in case of a node crash the state change can be recovered and replayed
        to restore the node state.

        Events produced by applying state change are also saved.
        """

        with self._lock:
            timestamp = datetime.utcnow().isoformat(timespec='milliseconds')
            state_change_id = self.storage.write_state_change(state_change, timestamp)
            self.state_change_id = state_change_id

            events = self.state_manager.dispatch(state_change)

            self.storage.write_events(state_change_id, events, timestamp)

        return events

    def snapshot(self):
        """ Snapshot the application state.

        Snapshots are used to restore the application state, either after a
        restart or a crash.
        """
        with self._lock:
            current_state = self.state_manager.current_state
            state_change_id = self.state_change_id

            # otherwise no state change was dispatched
            if state_change_id:
                self.storage.write_state_snapshot(state_change_id, current_state)

    @property
    def version(self):
        return self.storage.get_version()
