# -*- coding: utf-8 -*-
# pylint: disable=too-few-public-methods
from collections import namedtuple

Iteration = namedtuple('Iteration', ('new_state', 'events'))


class State(object):
    """ An isolated state, modified by StateChange messages.

    Notes:
    - Don't duplicate the same state data in two different States, instead use
    identifiers.
    - State objects may be nested.
    - These objects don't have logic by design.
    - These objects must not be mutated in-place.
    - This class is used as a marker for states.
    """
    pass


class StateChange(object):
    """ Declare the transition to be applied in a state object. (eg. a
    blockchain event, a new packet, an error).

    StateChanges are incoming events that change this node state. It is not
    used for the node to comunicate with the outer world.

    Notes:
    - A message changes a single State object.
    - Re-applying StateChanges must produce the same result.
    - These objects don't have logic by design.
    - This class is used as a marker for state changes.
    """
    pass


class Event(object):
    """ Events produced by the execution of a state change.

    Notes:
    - The state machine is oblivious of the different kinds of events.
    - This class is used as a marker for events.
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
        """ Apply the `state_change` in the current machine and return the
        resulting events.

        Args:
            state_change (StateChange): An object represention of a state
            change.

        Return:
            [Event]: A list of events produced by the state transition, it's
            the upper layer responsability to decided how to handle these
            events.
        """
        assert isinstance(state_change, StateChange)

        # update the current state by applying the change
        iteration = self.state_transition.apply_state_change(
            self.current_state,
            state_change,
        )

        assert isinstance(self.current_state, Iteration)

        self.current_state, events = iteration

        assert isinstance(self.current_state, State)
        assert all(isinstance(e, Event) for e in events)

        return events
