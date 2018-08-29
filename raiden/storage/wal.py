import structlog

from raiden.storage.serialize import JSONSerializer
from raiden.transfer.architecture import StateManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def compare_state_trees(state1, state2):
    print('> Looking at', state1.__class__.__name__)
    if not state1.__class__.__name__ == state2.__class__.__name__:
        print(
            'Instances do not have same type:',
            state1.__class__.__name__,
            state2.__class__.__name__,
        )
        return

    if isinstance(state1, dict):
        if state1.keys() != state2.keys():
            print('dics do not have same keys:', state1.keys(), state2.keys())
        else:
            for k in state1.keys():
                compare_state_trees(state1[k], state2[k])
    elif isinstance(state1, list):
        if len(state1) != len(state2):
            print('lists do not have same length:', len(state1), len(state2))
        else:
            for i in range(len(state1)):
                compare_state_trees(state1[i], state2[i])
    else:
        slots1 = state1.__slots__
        slots2 = state2.__slots__

        if not slots1 == slots2:
            print('Instances do not have same slots:', slots1, slots2)
            return

        for attr_name in state1.__slots__:
            if attr_name in ('pseudo_random_generator'):
                return

            print('> Comparing', attr_name)

            attr1 = getattr(state1, attr_name)
            attr2 = getattr(state2, attr_name)

            if not attr1 == attr2:
                from raiden.transfer.state import State
                print('Instances do not have same value:', attr1, attr2)
                if isinstance(attr1, (State, dict, list)):
                    print('... Recurse into compare_state_trees')
                    compare_state_trees(attr1, attr2)
            else:
                print('>>> Matching')


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
    for i, state_change in enumerate(unapplied_state_changes):

        # FIXME: This is just temporary to make sure our json serialization code works
        # check state serialization
        state = state_manager.current_state
        if state is not None:
            json = JSONSerializer.serialize(state)
            restored = JSONSerializer.deserialize(json)

            if state != restored:
                print('###########################################')
                compare_state_trees(state, restored)
            else:
                print(f'{i:>3}: State serialisation round-trip successful')

        # check state change serialization
        if state_change is not None:
            try:
                json = JSONSerializer.serialize(state_change)
                restored = JSONSerializer.deserialize(json)

                if state_change != restored:
                    print('Serialisation failed for:', state_change.__class__.__name__)
                else:
                    print('State change serialisation round-trip successful')
            except Exception:
                print('Serialisation failed for:', state_change.__class__.__name__)

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
