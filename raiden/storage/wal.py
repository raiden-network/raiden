from datetime import datetime

import gevent.lock
import structlog

from raiden.storage.sqlite import FIRST_ULID, Range, SerializedSQLiteStorage, StateChangeID
from raiden.transfer.architecture import Event, State, StateChange, StateManager
from raiden.utils.typing import Callable, Generic, List, RaidenDBVersion, Tuple, TypeVar

log = structlog.get_logger(__name__)


def restore_to_state_change(
    transition_function: Callable,
    storage: SerializedSQLiteStorage,
    state_change_identifier: StateChangeID,
) -> "WriteAheadLog":
    from_identifier: StateChangeID

    snapshot = storage.get_snapshot_before_state_change(
        state_change_identifier=state_change_identifier
    )

    if snapshot is not None:
        log.debug(
            "Restoring from snapshot",
            from_state_change_id=snapshot.state_change_identifier,
            to_state_change_id=state_change_identifier,
        )
        from_identifier = snapshot.state_change_identifier
        chain_state = snapshot.data
    else:
        log.debug(
            "No snapshot found, replaying all state changes",
            to_state_change_id=state_change_identifier,
        )
        from_identifier = StateChangeID(FIRST_ULID)
        chain_state = None

    unapplied_state_changes = storage.get_statechanges_by_range(
        Range(from_identifier, state_change_identifier)
    )

    state_manager = StateManager(transition_function, chain_state)
    wal = WriteAheadLog(state_manager, storage)

    log.debug("Replaying state changes", num_state_changes=len(unapplied_state_changes))
    for state_change in unapplied_state_changes:
        wal.state_manager.dispatch(state_change.data)

    return wal


ST = TypeVar("ST", bound=State)


class WriteAheadLog(Generic[ST]):
    state_change_id: StateChangeID

    def __init__(self, state_manager: StateManager[ST], storage: SerializedSQLiteStorage) -> None:
        self.state_manager = state_manager
        self.storage = storage

        # The state changes must be applied in the same order as they are saved
        # to the WAL. Because writing to the database context switches, and the
        # scheduling is undetermined, a lock is necessary to protect the
        # execution order.
        self._lock = gevent.lock.Semaphore()

    def log_and_dispatch(self, state_change: StateChange) -> Tuple[ST, List[Event]]:
        """ Log and apply a state change.

        This function will first write the state change to the write-ahead-log,
        in case of a node crash the state change can be recovered and replayed
        to restore the node state.

        Events produced by applying state change are also saved.
        """

        with self._lock:
            timestamp = datetime.utcnow()
            state_change_id = self.storage.write_state_change(state_change, timestamp)
            self.state_change_id = state_change_id

            state, events = self.state_manager.dispatch(state_change)

            self.storage.write_events(state_change_id, events, timestamp)

        return state, events

    def snapshot(self) -> None:
        """ Snapshot the application state.

        Snapshots are used to restore the application state, either after a
        restart or a crash.
        """
        with self._lock:
            current_state = self.state_manager.current_state
            state_change_id = self.state_change_id
            timestamp = datetime.utcnow()

            # otherwise no state change was dispatched
            if state_change_id and current_state is not None:
                self.storage.write_state_snapshot(current_state, state_change_id, timestamp)

    @property
    def version(self) -> RaidenDBVersion:
        return self.storage.get_version()
