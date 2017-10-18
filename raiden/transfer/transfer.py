# -*- coding: utf-8 -*-

from raiden.transfer.architecture import TransitionResult
from raiden.transfer.mediated_transfer import (
    initiator,
    mediator,
    target,
)
from raiden.transfer.mediated_transfer.state import (
    InitiatorState,
    MediatorState,
    TargetState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ActionInitTarget,
    ReceiveBalanceProof,
    ReceiveSecretRequest,
)


def dispatch_to_subtasks(all_sub_tasks, state_change):
    events = []
    new_sub_tasks = []

    for subtask in all_sub_tasks:
        if isinstance(subtask, InitiatorState):
            iteration = initiator.state_transition(
                subtask,
                state_change,
            )

        elif isinstance(subtask, MediatorState):
            iteration = mediator.state_transition(
                subtask,
                state_change,
            )

        elif isinstance(subtask, TargetState):
            iteration = target.state_transition(
                subtask,
                state_change,
            )

        events.extend(iteration.events)

        if iteration.new_state is not None:
            new_sub_tasks.append(iteration.new_state)

    return new_sub_tasks, events


def dispatch_to_all(next_state, state_change):
    events = []
    new_identifier_to_transfers = {}

    for id_, substasks in next_state.identifier_to_transfers.items():
        new_sub_tasks, events = dispatch_to_subtasks(
            substasks,
            state_change,
        )
        events.extend(events)

        new_identifier_to_transfers[id_] = new_sub_tasks

    return new_identifier_to_transfers, events


def state_transition(next_state, state_change):
    if isinstance(state_change, (ReceiveBalanceProof, ReceiveSecretRequest)):
        identifier = state_change.identifier
        subtasks = next_state.identifier_to_transfers.get(identifier)

        if subtasks:
            new_sub_tasks, events = dispatch_to_subtasks(
                subtasks,
                state_change,
            )

            if new_sub_tasks:
                next_state.identifier_to_transfers[identifier] = new_sub_tasks
            else:
                del next_state.identifier_to_transfers[identifier]

            iteration = TransitionResult(
                next_state,
                events,
            )
        else:
            iteration = TransitionResult(
                next_state,
                [],
            )

    elif isinstance(state_change, ActionInitInitiator):
        identifier = state_change.transfer.identifier
        iteration = initiator.state_transition(None, state_change)
        subtasks = next_state.identifier_to_transfers.setdefault(identifier, [])
        subtasks.append(iteration.new_state)
        events = iteration.events

        iteration = TransitionResult(
            next_state,
            events,
        )

    elif isinstance(state_change, ActionInitMediator):
        identifier = state_change.from_transfer.identifier
        iteration = mediator.state_transition(None, state_change)
        subtasks = next_state.identifier_to_transfers.setdefault(identifier, [])
        subtasks.append(iteration.new_state)
        events = iteration.events

        iteration = TransitionResult(
            next_state,
            events,
        )

    elif isinstance(state_change, ActionInitTarget):
        identifier = state_change.from_transfer.identifier
        iteration = target.state_transition(None, state_change)
        subtasks = next_state.identifier_to_transfers.setdefault(identifier, [])
        subtasks.append(iteration.new_state)
        events = iteration.events

        iteration = TransitionResult(
            next_state,
            events,
        )

    else:
        new_identifier_to_transfers, events = dispatch_to_all(
            next_state,
            state_change,
        )
        next_state.identifier_to_transfers = new_identifier_to_transfers

        iteration = TransitionResult(
            next_state,
            events,
        )

    return iteration
