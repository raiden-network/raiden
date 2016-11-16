# -*- coding: utf-8 -*-
# pylint: disable=too-few-public-methods
from collections import namedtuple

Iteration = namedtuple('Iteration', ('new_state', 'actions'))


class State(object):
    """ A isolated state representation, modified by application StateChange
    messages.

    Notes:
    - Do not duplicate the same state data in two State subclasses, instead of
    nesting use identifiers.
    - These objects contain the application state and no logic by design.
    """
    pass


class StateChange(object):
    """ StateChange are used to inform the application when events happened
    (eg. a blockchain event, a new packet, an error).

    Notes:
    - Messages when applied change a single State object.
    - These objects need to be constructed in such a way that reaplying a
    complete log of StateChange reproduces the correct application state.
    - These objects represent state changes but don't have imperative code by
    design.
    - This subclass is used as a marker for StateChange.
    """
    pass


class StateManager(object):
    """ The storage for all the application state that can apply state
    trasintions. """

    def __init__(self, state_transition, current_state):
        """ Initialize the state manager.

        Args:
            state_transition: function that can apply the StateChange messages,
            it contains the business logic.
            current_state: Restore the application to the state of a previous
            run.
        """

        self.state_transition = state_transition
        self.current_state = current_state

    def dispatch(self, state_change):
        # update the current state by applying the change
        self.current_state = self.state_transition.apply_state_change(
            self.current_state,
            state_change,
        )
