# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import Iteration
from raiden.transfer.state import InitiatorState, RoutesState
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.state_change import (
    Blocknumber,
    CancelMediatedTransfer,
    CancelTimeout,
    GetRoutes,
    InitInitiator,
    MediatedTransferMessageSend,
    NewSecret,
    RefundTransfer,
    RevealSecret,
    Route,
    Secret,
    SecretRequestReceived,
    Timeout,
    UnlockLock,
)

# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


def cancel_current_transfer(next_state):
    """ Discards the current secret and clear current state. """
    new_secret = NewSecret(next_state.transfer.identifier)

    next_state.routes.canceled_routes.append(next_state.route)
    next_state.canceled_transfers.append(next_state.message)

    next_state.secret = None
    next_state.hashlock = None
    next_state.message = None
    next_state.route = None
    next_state.secretrequest = None

    iteration = Iteration(next_state, [new_secret])

    return iteration


def state_transition(current_state, state_change):
    """ State machine for a node starting a mediated transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    state_uninitialized = True
    state_wait_routes = False
    state_send_transfer = False
    state_wait_secretrequest = False
    state_wait_unlock = False

    if current_state is not None:
        state_uninitialized = False
        state_wait_routes = current_state.routes is None
        state_send_transfer = current_state.secretrequest is None
        state_wait_secretrequest = current_state.secretrequest is not None
        state_wait_unlock = current_state.revealsecret is not None

    iteration = Iteration(current_state, list())
    next_state = deepcopy(current_state)

    if not state_uninitialized:
        if isinstance(state_change, Blocknumber):
            next_state.block_number = state_change.block_number

        elif isinstance(state_change, Route):
            update_route(next_state, state_change)

    # Init state and request routes
    if state_uninitialized:
        if isinstance(state_change, InitInitiator):
            our_address = state_change.our_address
            transfer = state_change.transfer
            block_number = state_change.block_number

            next_state = InitiatorState(
                our_address,
                transfer,
                block_number,
            )

            get_routes = GetRoutes(
                transfer.identifier,
                transfer.target,
                transfer.token,
            )

            iteration = Iteration(next_state, [get_routes])

    # Set the routes and request a secret
    elif state_wait_routes:
        valid_routes = (
            isinstance(state_change, list) and
            all(isinstance(item, Route) for item in state_change) and
            all(item.transfer_id == current_state.transfer.identifier for item in state_change)
        )

        if valid_routes:
            next_state.routes = RoutesState([
                route
                for route in state_change
                if route.state == 'available'
            ])
            new_secret = NewSecret(next_state.transfer.identifier)

            iteration = Iteration(next_state, [new_secret])

    # Got a new secret, choose a route and send the transfer message
    elif state_send_transfer:
        if isinstance(state_change, Secret):
            next_state.secret = state_change.secret
            next_state.hashlock = state_change.hashlock

            try_route = None
            while next_state.routes.available_routes:
                route = next_state.routes.available_routes.pop()

                if route.capacity < next_state.transfer.amount:
                    next_state.routes.ignored_routes.append(route)
                else:
                    try_route = route
                    break

            # no avaiable route has sufficient capacity for the current
            # transfer, cancel it
            if try_route is None:
                cancel = CancelMediatedTransfer(
                    transfer_id=next_state.transfer.identifier,
                )
                iteration = Iteration(None, [cancel])

            else:
                lock_timeout = try_route.settle_timeout - try_route.reveal_timeout
                lock_expiration = next_state.block_number + lock_timeout
                message_id = len(next_state.canceled_transfers)

                # This message is implicitely expirable
                message = MediatedTransferMessageSend(
                    next_state.transfer.identifier,
                    message_id,
                    next_state.transfer.token,
                    next_state.transfer.amount,
                    lock_expiration,
                    next_state.hashlock,
                    next_state.transfer.target,
                    try_route.node_address,
                )
                next_state.message = message

                iteration = Iteration(next_state, [message])

    # Target received the mediated transfer, check the transfer and reveal the
    # secret
    elif state_wait_secretrequest:

        if isinstance(state_change, SecretRequestReceived):
            valid_secretrequest = (
                state_change.transfer_id == next_state.transfer.id and
                state_change.amount == next_state.transfer.amount and
                state_change.hashlock == next_state.hashlock and
                state_change.identifier == next_state.transfer.identifier and
                state_change.sender == next_state.transfer.target
            )

            invalid_secretrequest = not valid_secretrequest
        else:
            valid_secretrequest = False
            invalid_secretrequest = False

        refund_transfer = (
            isinstance(state_change, RefundTransfer) and
            state_change.sender == next_state.route.node_address
        )
        timeout = isinstance(state_change, Timeout)

        if valid_secretrequest:
            reveal_secret = RevealSecret(
                next_state.transfer.id,
                next_state.secret,
                next_state.transfer.target,
                next_state.our_address,
            )
            cancel_timeout = CancelTimeout(
                next_state.transfer.id,
                next_state.route.node_address,
            )

            next_state.revealsecret = reveal_secret
            iteration = Iteration(next_state, [reveal_secret, cancel_timeout])

        elif invalid_secretrequest or refund_transfer or timeout:
            return cancel_current_transfer(next_state)

    # next hop learned the secret, unlock the token locally and allow
    # send the withdraw message to next hop
    elif state_wait_unlock:
        secret_reveal = (
            isinstance(state_change, RevealSecret) and
            state_change.sender == next_state.route.node_address
        )

        if secret_reveal:
            unlock_lock = UnlockLock(
                next_state.transfer.identifier,
                next_state.route.node_address,
                next_state.transfer.token,
                next_state.secret,
                next_state.hashlock,
            )

            iteration = Iteration(None, [unlock_lock])

    return iteration
