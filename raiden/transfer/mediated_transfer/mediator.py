# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import Iteration
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.state import MediatorState, RoutesState
from raiden.transfer.state_change import (
    Blocknumber,
    CancelMediatedTransferMessage,
    CancelTimeout,
    GetRoutes,
    InitMediator,
    MediatedTransferMessageSend,
    RefundTransfer,
    RegisterSecret,
    RevealSecret,
    Route,
    Secret,
    Timeout,
    UnlockLock,
    WithdrawLock,
)
from raiden.utils import sha3


def try_next_route(next_state):
    actions = list()

    if next_state.route is not None:
        cancel_timeout = CancelTimeout(
            next_state.transfer.id,
            next_state.routes.node_address,
        )
        actions.append(cancel_timeout)

    try_route = None
    while next_state.routes.available_routes:
        route = next_state.routes.available_routes.pop()
        reveal_expiration = route.reveal_timeout + next_state.block_number

        # `reveal_timeout` is the number of blocks configured as a safe guard
        # against DoS attacks to the ethereum, a node must only forward a
        # mediated transfer if it can guarantee this timeout.
        under_reveal_expiration = next_state.originating_transfer.expiration <= reveal_expiration

        if route.capacity < next_state.transfer.amount or under_reveal_expiration:
            next_state.routes.ignored_routes.append(route)
        else:
            try_route = route
            break

    # No route found, refund the previous hop so that it can try a new route.
    if try_route is None:
        refund = RefundTransfer(
            next_state.transfer.identifier,
            next_state.transfer.amount,
            next_state.hashlock,
            next_state.sender,
        )
        next_state.sent_refund = refund

        next_state.route = None
        next_state.message = None

        actions.append(refund)
        iteration = Iteration(next_state, cancel_timeout)

    else:
        lock_timeout = (
            next_state.originating_transfer.expiration -
            next_state.block_number
        )
        new_lock_timeout = lock_timeout - try_route.reveal_timeout

        # A timeout larger than settle_timeout will be rejected. This /needs/
        # to be validated in state_initialize.
        if new_lock_timeout > try_route.settle_timeout:
            new_lock_timeout = try_route.settle_timeout - try_route.reveal_timeout

        message_id = len(next_state.sent_transfers_refunded)
        new_lock_expiration = new_lock_timeout + next_state.block_number
        message = MediatedTransferMessageSend(
            next_state.transfer.id,
            message_id,
            next_state.transfer.token,
            next_state.transfer.amount,
            new_lock_expiration,
            next_state.hashlock,
            next_state.target,
            try_route.node_address,
        )
        next_state.message = message

        actions.append(message)
        iteration = Iteration(next_state, actions)

    return iteration


def state_transition(current_state, state_change):
    """ State machine for a node mediating a transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    state_uninitialized = True
    state_wait_routes = False
    state_wait_secret = False
    state_wait_withdraw = False

    if current_state is None:
        state_uninitialized = False
        state_wait_routes = current_state.routes is None
        state_wait_secret = current_state.message is not None
        state_wait_withdraw = current_state.secret is not None

    iteration = Iteration(current_state, list())
    next_state = deepcopy(current_state)

    if not state_uninitialized:
        if isinstance(state_change, Blocknumber):
            next_state.block_number = state_change.block_number

        elif isinstance(state_change, Route):
            update_route(next_state, state_change)

    # Init state and request routes
    if state_uninitialized:
        if isinstance(state_change, InitMediator):
            our_address = state_change.our_address
            target = state_change.target
            transfer = state_change.transfer
            originating_route = state_change.originating_route
            originating_transfer = state_change.originating_transfer
            block_number = state_change.block_number

            next_state = MediatorState(
                our_address,
                transfer,
                target,
                originating_route,
                originating_transfer,
                block_number,
            )

            settle_expiration = originating_route.settle_timeout + state_change.block_number
            over_settle_expiration = originating_transfer.expiration >= settle_expiration

            # An expiration /must/ be lower than settle_timeout, otherwise we
            # cannot guarantee the transfer will settled.
            # TODO: It may be valid to relax this constraint, given that the
            # node is online when the channel is closed.
            #
            # Notes:
            # - This node didn't send a transfer forward, so it can not lose
            #   asset.
            # - The previous_node knowns the settle_timeout because this value
            #   is in the smart contract.
            # - It's not sending a RefundTransfer to the previous_node, so it
            #   will force a retry with a new path/different hashlock, this
            #   could make the bad behaving node lose it's fees but it will
            #   also increase latency.
            if over_settle_expiration:
                iteration = Iteration(None, [])

            else:
                get_routes = GetRoutes(
                    transfer.identifier,
                    target,
                    transfer.token,
                )

                iteration = Iteration(next_state, [get_routes])

    # Set the routes and mediate the transfer
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

            iteration = try_next_route(next_state)

    elif state_wait_secret:
        valid_refund = (
            isinstance(state_change, RefundTransfer) and
            state_change.identifier == state_change.message.identifier and
            state_change.amount == state_change.message.amount and
            state_change.hashlock == state_change.message.hashlock and
            state_change.sender == next_state.message.node_address
        )

        valid_reveal_secret = (
            isinstance(state_change, RevealSecret) and
            sha3(state_change.secret) == next_state.hashlock
        )

        timeout = isinstance(state_change, Timeout)

        if valid_refund:
            next_state.routes.refund_routes.append(next_state.route)
            next_state.sent_transfers_refunded.append(next_state.message)

            iteration = try_next_route(next_state)

        elif valid_reveal_secret:
            next_state.secret = state_change.secret

            register = RegisterSecret(
                state_change.originating_transfer.transfer.identifier,
                state_change.secret,
            )
            cancel_timeout = CancelTimeout(
                next_state.transfer.id,
                next_state.route.node_address,
            )
            reveal = RevealSecret(
                next_state.originating_transfer.identifier,
                next_state.secret,
                next_state.originating_route.node_address,
                next_state.our_address,
            )

            unlocks = [
                UnlockLock(
                    refunded_transfer.identifier,
                    refunded_transfer.node_address,
                    next_state.originating_transfer.token,
                    next_state.secret,
                    next_state.hashlock,
                )
                for refunded_transfer in next_state.sent_transfers_refunded
            ]
            iteration = Iteration(next_state, [register, cancel_timeout, reveal] + unlocks)

        elif timeout:
            cancel_message = CancelMediatedTransferMessage(
                transfer_id=next_state.transfer.transfer_id,
                message_id=next_state.message.message_id
            )

            next_state.cancel = cancel_message
            next_state.hashlock = None
            next_state.message = None
            next_state.route = None

            iteration = Iteration(next_state, [cancel_message])

    elif state_wait_withdraw:
        valid_secret = (
            isinstance(state_change, Secret) and
            state_change.sender == next_state.originating_transfer.sender
        )

        if valid_secret:
            withdraw = WithdrawLock(
                next_state.originating_transfer.id,
                next_state.originating_transfer.token,
                next_state.secret,
                next_state.hashlock,
            )
            iteration = Iteration(None, [withdraw])

    return iteration
