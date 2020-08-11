from abc import abstractmethod, ABC
from contextlib import contextmanager
from dataclasses import dataclass

import gevent.lock
import structlog

from raiden.storage.serialization import DictSerializer
from raiden.storage.sqlite import (
    LOW_STATECHANGE_ULID,
    Range,
    SerializedSQLiteStorage,
    StateChangeID,
)
from raiden.transfer.architecture import Event, State, StateChange, StateManager
from raiden.utils.formatting import to_checksum_address
from raiden.utils.logging import redact_secret
from raiden.utils.typing import (
    Address,
    Callable,
    Generic,
    List,
    Optional,
    RaidenDBVersion,
    Tuple,
    TypeVar,
)

log = structlog.get_logger(__name__)


def restore_to_state_change(
    transition_function: Callable,
    storage: SerializedSQLiteStorage,
    state_change_identifier: StateChangeID,
    node_address: Address,
) -> Tuple[int, int, "WriteAheadLog"]:
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
            node=to_checksum_address(node_address),
        )
        from_identifier = snapshot.state_change_identifier
        chain_state = snapshot.data
        state_change_qty = snapshot.state_change_qty
    else:
        log.debug(
            "No snapshot found, replaying all state changes",
            to_state_change_id=state_change_identifier,
            node=to_checksum_address(node_address),
        )
        from_identifier = LOW_STATECHANGE_ULID
        chain_state = None
        state_change_qty = 0

    state_manager = StateManager(transition_function, chain_state)
    wal = WriteAheadLog(state_manager, storage)

    unapplied_state_changes = storage.get_statechanges_by_range(
        Range(from_identifier, state_change_identifier)
    )
    if unapplied_state_changes:
        log.debug(
            "Replaying state changes",
            replayed_state_changes=[
                redact_secret(DictSerializer.serialize(state_change))
                for state_change in unapplied_state_changes
            ],
            node=to_checksum_address(node_address),
        )
        wal.state_manager.dispatch(unapplied_state_changes)

    return state_change_qty, len(unapplied_state_changes), wal


ST = TypeVar("ST", bound=State)


@dataclass(frozen=True)
class SavedState(Generic[ST]):
    """Saves the state and the id of the state change that produced it.

    This datastructure keeps the state and the state_change_id synchronized.
    Having these values available is useful for debugging.
    """

    state_change_id: StateChangeID
    state: ST


class AtomicStateChangeDispatcher(ABC, Generic[ST]):
    @abstractmethod
    def dispatch(self, state_change: StateChange) -> Tuple[ST, List[Event]]:
        """
        EXPLAIN THE REASONING BEHIND THAT CLASS
        """


class WriteAheadLog(Generic[ST]):
    saved_state: SavedState[ST]

    def __init__(self, state_manager: StateManager[ST], storage: SerializedSQLiteStorage) -> None:
        self.state_manager = state_manager
        self.storage = storage

        # The state changes must be applied in the same order as they are saved
        # to the WAL. Because writing to the database context switches, and the
        # scheduling is undetermined, a lock is necessary to protect the
        # execution order.
        self._lock = gevent.lock.Semaphore()

    @contextmanager
    def process_state_change_atomically(self) -> AtomicStateChangeDispatcher:
        """

        """
        class _AtomicStateChangeDispatcher(AtomicStateChangeDispatcher, Generic[ST]):
            def __init__(self, state_manager: StateManager[ST], storage: SerializedSQLiteStorage) -> None:
                self.state_manager = state_manager
                self.storage = storage

            def dispatch(self, state_change: StateChange) -> Tuple[ST, List[Event]]:
                next_state, events = self.state_manager.dispatch(state_change)
                self._write_state_changes_and_corresponding_events(state_change, events)
                return next_state, events

            def _save_data(self, data: List[ST, List[Event]]):


        with self._lock, self.storage as transaction:
            copied_state = self.state_manager.copy()
            yield _AtomicStateChangeDispatcher(state_manager=copied_state, transaction=transaction)

    def snapshot(self, statechange_qty: int) -> None:
        """ Snapshot the application state.

        Snapshots are used to restore the application state, either after a
        restart or a crash.
        """
        with self._lock:
            current_state = self.state_manager.current_state
            state_change_id = self.saved_state.state_change_id

            # otherwise no state change was dispatched
            if state_change_id and current_state is not None:
                self.storage.write_state_snapshot(current_state, state_change_id, statechange_qty)

    @property
    def version(self) -> RaidenDBVersion:
        return self.storage.get_version()
