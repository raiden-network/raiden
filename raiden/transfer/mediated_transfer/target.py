# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.utils import sha3
from raiden.transfer.architecture import Iteration
from raiden.transfer.mediated_transfer.state import TargetState
from raiden.transfer.state_change import (
    Block,
    ActionInitTarget,
    ReceiveSecretReveal,
    Secret,
    SendSecretRequest,
    WithdrawLock,
)


def state_transition(state, state_change):
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if state is None:
        state_uninitialized = True
        state_wait_secret = False
        state_wait_withdraw = False
    else:
        state_uninitialized = False
        state_wait_secret = state.secret is None
        state_wait_withdraw = state.secret is not None

    iteration = Iteration(state, list())

    if not state_uninitialized:
        if isinstance(state_change, Block):
            state.block_number = state_change.block_number

    if state_uninitialized:
        if isinstance(state_change, ActionInitTarget):
            our_address = state_change.our_address
            target = state_change.target
            from_route = state_change.from_route
            from_transfer = state_change.from_transfer
            hashlock = state_change.hashlock
            block_number = state_change.block_number

            state = TargetState(
                our_address,
                target,
                from_route,
                from_transfer,
                hashlock,
                block_number,
            )

            secret_request = SendSecretRequest(
                from_transfer.identifier,
                from_transfer.amount,
                from_transfer.hashlock,
            )
            state.secret_request = secret_request

            iteration = Iteration(state, [secret_request])

    elif state_wait_secret:
        secret_reveal = (
            isinstance(state_change, ReceiveSecretReveal) and
            sha3(state_change.secret) == state.hashlock
        )

        if secret_reveal:
            state.secret = state_change.secret

            reveal = ReceiveSecretReveal(
                state.from_transfer.identifier,
                state.secret,
                state.from_route.node_address,
                state.our_address,
            )

            iteration = Iteration(state, [reveal])

    elif state_wait_withdraw:
        valid_secret = (
            isinstance(state_change, Secret) and
            state_change.sender == state.from_transfer.sender
        )

        if valid_secret:
            withdraw = WithdrawLock(
                state.from_transfer.identifier,
                state.from_transfer.token,
                state.secret,
                state.hashlock,
            )
            iteration = Iteration(None, [withdraw])

    return iteration
