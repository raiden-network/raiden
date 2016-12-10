# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.utils import sha3
from raiden.transfer.architecture import Iteration
from raiden.transfer.mediated_transfer.state import TargetState
from raiden.transfer.state_change import (
    Blocknumber,
    InitTarget,
    RevealSecret,
    Secret,
    SecretRequestMessageSend,
    WithdrawLock,
)


def state_transition(current_state, state_change):
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    state_uninitialized = current_state is None
    state_wait_secret = current_state.secret is None
    state_wait_withdraw = current_state.secret is not None

    iteration = Iteration(current_state, list())
    next_state = deepcopy(current_state)

    if not state_uninitialized:
        if isinstance(state_change, Blocknumber):
            next_state.block_number = state_change.block_number

    if state_uninitialized:
        if isinstance(state_change, InitTarget):
            our_address = state_change.our_address
            target = state_change.target
            originating_route = state_change.originating_route
            originating_transfer = state_change.originating_transfer
            hashlock = state_change.hashlock
            block_number = state_change.block_number

            next_state = TargetState(
                our_address,
                target,
                originating_route,
                originating_transfer,
                hashlock,
                block_number,
            )

            secret_request = SecretRequestMessageSend(
                originating_transfer.identifier,
                originating_transfer.amount,
                originating_transfer.hashlock,
            )
            next_state.secret_request = secret_request

            iteration = Iteration(next_state, [secret_request])

    elif state_wait_secret:
        secret_reveal = (
            isinstance(state_change, RevealSecret) and
            sha3(state_change.secret) == next_state.hashlock
        )

        if secret_reveal:
            next_state.secret = state_change.secret

            reveal = RevealSecret(
                next_state.originating_transfer.identifier,
                next_state.secret,
                next_state.originating_route.node_address,
                next_state.our_address,
            )

            iteration = Iteration(next_state, [reveal])

    elif state_wait_withdraw:
        valid_secret = (
            isinstance(state_change, Secret) and
            state_change.sender == next_state.originating_transfer.sender
        )

        if valid_secret:
            withdraw = WithdrawLock(
                next_state.originating_transfer.identifier,
                next_state.originating_transfer.token,
                next_state.secret,
                next_state.hashlock,
            )
            iteration = Iteration(None, [withdraw])

    return iteration
