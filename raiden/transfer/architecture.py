# -*- coding: utf-8 -*-
# pylint: disable=too-few-public-methods
from collections import namedtuple

Iteration = namedtuple('Iteration', ('new_state', 'actions'))


class State(object):
    """ An isolated state, modified by StateChange messages.

    Notes:
    - Don't duplicate the same state data in two different States, instead use
    identifiers.
    - These objects don't have logic by design.
    - These objects must not be mutated in-place.
    - This class is used as a marker for states.
    """
    pass


class StateChange(object):
    """ Declare the transition to be applied in a state object. (eg. a
    blockchain event, a new packet, an error).

    Notes:
    - Messages change a single State object.
    - Reaplying StateChanges must produce the same result.
    - These objects don't have logic by design.
    - This class is used as a marker for state changes.
    """
    pass


class StateManager(object):
    """ The mutable storage for the application state, this storage can do
    state transitions by applying the StateChanges to the current State.
    """

    def __init__(self, state_transition, current_state):
        """ Initialize the state manager.

        Args:
            state_transition: function that can apply the a StateChange
            message.
            current_state: current application state.
        """
        self.state_transition = state_transition
        self.current_state = current_state

    def dispatch(self, state_change):
        # update the current state by applying the change
        self.current_state = self.state_transition.apply_state_change(
            self.current_state,
            state_change,
        )
