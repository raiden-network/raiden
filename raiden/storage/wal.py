import gevent.lock
import structlog

from raiden.storage.sqlite import (
    LOW_STATECHANGE_ULID,
    Range,
    SerializedSQLiteStorage,
    StateChangeID,
)
from raiden.transfer.architecture import Event, State, StateChange, StateManager
from raiden.utils.typing import Callable, Generic, List, Optional, RaidenDBVersion, Tuple, TypeVar

log = structlog.get_logger(__name__)


def restore_to_state_change(
    transition_function: Callable,
    storage: SerializedSQLiteStorage,
    state_change_identifier: StateChangeID,
) -> "WriteAheadLog":
    chain_state: Optional[State]
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
        from_identifier = LOW_STATECHANGE_ULID
        chain_state = None

    state_manager = StateManager(transition_function, chain_state)
    wal = WriteAheadLog(state_manager, storage)

    unapplied_state_changes = storage.get_statechanges_by_range(
        Range(from_identifier, state_change_identifier)
    )
    if unapplied_state_changes:
        log.debug("Replaying state changes", state_changes=unapplied_state_changes)
        wal.state_manager.dispatch(unapplied_state_changes)

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

    def log_and_dispatch(self, state_changes: List[StateChange]) -> Tuple[ST, List[Event]]:
        """ Log and apply a state change.

        This function will first write the state change to the write-ahead-log,
        in case of a node crash the state change can be recovered and replayed
        to restore the node state.

        Events produced by applying state change are also saved.
        """

        with self._lock:
            all_state_change_ids = self.storage.write_state_changes(state_changes)
            self.state_change_id = all_state_change_ids[-1]

            latest_state, all_events = self.state_manager.dispatch(state_changes)

            event_data = list()
            flattened_events = list()
            for state_change_id, events in zip(all_state_change_ids, all_events):
                flattened_events.extend(events)
                for event in events:
                    event_data.append((state_change_id, event))

            self.storage.write_events(event_data)

        return latest_state, flattened_events

    def snapshot(self) -> None:
        """ Snapshot the application state.

        Snapshots are used to restore the application state, either after a
        restart or a crash.
        """
        with self._lock:
            current_state = self.state_manager.current_state
            state_change_id = self.state_change_id

            # otherwise no state change was dispatched
            if state_change_id and current_state is not None:
                self.storage.write_state_snapshot(current_state, state_change_id)

    @property
    def version(self) -> RaidenDBVersion:
        return self.storage.get_version()
