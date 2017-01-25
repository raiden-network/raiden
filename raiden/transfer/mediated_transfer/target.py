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


def state_transition(next_state, state_change):
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if next_state is None:
        state_uninitialized = True
        state_wait_secret = False
        state_wait_withdraw = False
    else:
        state_uninitialized = False
        state_wait_secret = next_state.secret is None
        state_wait_withdraw = next_state.secret is not None

    iteration = Iteration(next_state, list())

    if not state_uninitialized:
        if isinstance(state_change, Blocknumber):
            next_state.block_number = state_change.block_number

    if state_uninitialized:
        if isinstance(state_change, InitTarget):
            our_address = state_change.our_address
            target = state_change.target
            from_route = state_change.from_route
            from_transfer = state_change.from_transfer
            hashlock = state_change.hashlock
            block_number = state_change.block_number

            next_state = TargetState(
                our_address,
                target,
                from_route,
                from_transfer,
                hashlock,
                block_number,
            )

            secret_request = SecretRequestMessageSend(
                from_transfer.identifier,
                from_transfer.amount,
                from_transfer.hashlock,
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
                next_state.from_transfer.identifier,
                next_state.secret,
                next_state.from_route.node_address,
                next_state.our_address,
            )

            iteration = Iteration(next_state, [reveal])

    elif state_wait_withdraw:
        valid_secret = (
            isinstance(state_change, Secret) and
            state_change.sender == next_state.from_transfer.sender
        )

        if valid_secret:
            withdraw = WithdrawLock(
                next_state.from_transfer.identifier,
                next_state.from_transfer.token,
                next_state.secret,
                next_state.hashlock,
            )
            iteration = Iteration(None, [withdraw])

    return iteration
