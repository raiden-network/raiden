# -*- coding: utf-8 -*-
from collections import namedtuple

from raiden.transfer.architecture import StateManager

InternalEvent = namedtuple(
    'InternalEvent',
    ('identifier', 'state_change_id', 'block_number', 'event_object'),
)


class WriteAheadLog:
    def __init__(self, transition_function, storage):
        # TODO:
        # - reapply missing state changes
        # - clear existing events for the unapplied state changes
        snapshot = storage.get_state_snapshot()
        state_manager = StateManager(transition_function, snapshot)

        self.state_manager = state_manager
        self.state_change_id = None
        self.storage = storage

    def log_and_dispatch(self, state_change, block_number):
        """ Log and apply a state change.

        This function will first write the state change to the write-ahead-log,
        in case of a node crash the state change can be recovered and replayed
        to restore the node state.

        Events produced by applying state change are also saved.
        """
        state_change_id = self.storage.write_state_change(state_change)

        events = self.state_manager.dispatch(state_change)

        self.state_change_id = state_change_id
        self.storage.write_events(state_change_id, block_number, events)

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
