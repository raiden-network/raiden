# -*- coding: utf-8 -*-
# pylint: disable=too-few-public-methods
from copy import deepcopy
from typing import List


# Quick overview
# --------------
#
# Goals:
# - Reliable failure recovery.
#
# Approach:
# - Use a write-ahead-log for state changes. Under a node restart the
# latest state snapshot can be recovered and the pending state changes
# reaplied.
#
# Requirements:
# - The function call `state_transition(curr_state, state_change)` must be
# deterministic, the recovery depends on the re-execution of the state changes
# from the WAL and must produce the same result.
# - StateChange must be idenpotent because the partner node might be recovering
# from a failure and a Event might be produced more than once.
#
# Requirements that are enforced:
# - A state_transition function must not produce a result that must be further
# processed, i.e. the state change must be self contained and the result state
# tree must be serializable to produce a snapshot. To enforce this inputs and
# outputs are separated under different class hierarquies (StateChange and Event).


class FlatInheritance(type):
    """ Nested inheritance is forbidden for architecture classes.

    The design choices adopted by this architecture rely heavily on dynamic
    dispatching based on type checking, e.g.::

        if isintance(obj, StopStateChange):
            handle_stop(state, obj)
        elif isintance(obj, StopWithCareStateChange):
            handle_stop_with_care(state, obj)

    For the above snippet to work, it's important for StopWithCareStateChange
    to not be a subclass of StopStateChange, otherwise the order of the
    statements used for the dynamic dispatch matter, leading to subtle bugs
    like the one above.
    """

    def __new__(mcs, name, bases, namespace, **kwds):  # pylint: disable=unused-argument
        # A marker is a special class type, used to describe one of the
        # components in the architecture, e.g. the State class.
        is_new_marker = not bases

        if not is_new_marker:
            # Enforce inheritance of at most one marker.
            #
            # Only one kind of marker may be used::
            #
            #      class Incorrect(State, StateChange): pass
            #
            # And a marker may be used at most once::
            #
            #      class Incorrect(State, State): pass
            #
            markers = [base for base in bases if isinstance(base, FlatInheritance)]
            assert len(markers) == 1, FlatInheritance.__doc__

            # Enforce a flat inheritance for the marker::
            #
            #      class Correct(State): pass
            #      class Incorrect(Correct): pass
            marker = markers[0]
            is_nested = any(isinstance(base, FlatInheritance) for base in marker.__bases__)
            assert not is_nested, FlatInheritance.__doc__

        return type.__new__(mcs, name, bases, dict(namespace))


class State(metaclass=FlatInheritance):
    """ An isolated state, modified by StateChange messages.

    Notes:
    - Don't duplicate the same state data in two different States, instead use
    identifiers.
    - State objects may be nested.
    - State classes don't have logic by design.
    - Each iteration must operate on fresh copy of the state, treating the old
          objects as immutable.
    - This class is used as a marker for states.
    """
    __slots__ = ()


class StateChange(metaclass=FlatInheritance):
    """ Declare the transition to be applied in a state object.

    StateChanges are incoming events that change this node state (eg. a
    blockchain event, a new packet, an error). It is not used for the node to
    communicate with the outer world.

    Nomenclature convention:
    - 'Receive' prefix for protocol messages.
    - 'ContractReceive' prefix for smart contract logs.
    - 'Action' prefix for other interactions.

    Notes:
    - These objects don't have logic by design.
    - This class is used as a marker for state changes.
    """
    __slots__ = ()


class Event(metaclass=FlatInheritance):
    """ Events produced by the execution of a state change.

    Nomenclature convention:
    - 'Send' prefix for protocol messages.
    - 'ContractSend' prefix for smart contract function calls.
    - 'Event' for node events.

    Notes:
    - This class is used as a marker for events.
    - These objects don't have logic by design.
    - Separate events are preferred because there is a decoupling of what the
      upper layer will use the events for.
    """
    __slots__ = ()


class StateManager:
    """ The mutable storage for the application state, this storage can do
    state transitions by applying the StateChanges to the current State.
    """
    __slots__ = (
        'state_transition',
        'current_state',
    )

    def __init__(self, state_transition, current_state):
        """ Initialize the state manager.

        Args:
            state_transition: function that can apply a StateChange message.
            current_state: current application state.
        """
        if not callable(state_transition):
            raise ValueError('state_transition must be a callable')

        self.state_transition = state_transition
        self.current_state = current_state

    def dispatch(self, state_change: StateChange) -> List[Event]:
        """ Apply the `state_change` in the current machine and return the
        resulting events.

        Args:
            state_change: An object representation of a state
            change.

        Return:
            A list of events produced by the state transition.
            It's the upper layer's responsibility to decided how to handle
            these events.
        """
        assert isinstance(state_change, StateChange)

        # the state objects must be treated as immutable, so make a copy of the
        # current state and pass the copy to the state machine to be modified.
        next_state = deepcopy(self.current_state)

        # update the current state by applying the change
        iteration = self.state_transition(
            next_state,
            state_change,
        )

        assert isinstance(iteration, TransitionResult)

        self.current_state = iteration.new_state
        events = iteration.events

        assert isinstance(self.current_state, (State, type(None)))
        assert all(isinstance(e, Event) for e in events)

        return events

    def __eq__(self, other):
        return (
            isinstance(other, StateManager) and
            self.state_transition == other.state_transition and
            self.current_state == other.current_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class TransitionResult:
    """ Representes the result of applying a single state change.

    When a task is completed the new_state is set to None, allowing the parent
    task to cleanup after the child.
    """

    __slots__ = (
        'new_state',
        'events',
    )

    def __init__(self, new_state, events):
        self.new_state = new_state
        self.events = events

    def __eq__(self, other):
        return (
            isinstance(other, TransitionResult) and
            self.new_state == other.new_state and
            self.events == other.events
        )

    def __ne__(self, other):
        return not self.__eq__(other)
