# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import Iteration
from raiden.transfer.state import AvailableRoutesState
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.state_change import Blocknumber, RouteChange
from raiden.transfer.mediated_transfer.state import MediatorState, Cancel
from raiden.transfer.mediated_transfer.state_change import (
    InitMediator,
    RefundTransferReceived,
    RevealSecretReceived,
    UnlockLock,
    WithdrawLock,
)
from raiden.transfer.mediated_transfer.events import (
    CancelMediatedTransfer,
    RevealSecret,
    RefundTransfer,
    MediatedTransfer,
)
from raiden.utils import sha3


def try_next_route(next_state):
    try_route = None
    while next_state.routes.available_routes:
        route = next_state.routes.available_routes.pop()
        reveal_expiration = route.reveal_timeout + next_state.block_number

        # `reveal_timeout` is the minimum number of blocks required to safely
        # forward a lock.
        good_reveal_expiration = next_state.from_transfer.lock.expiration > reveal_expiration
        good_capacity = route.capacity > next_state.from_transfer.lock.amount

        if good_reveal_expiration and good_capacity:
            try_route = route
            break
        else:
            next_state.routes.ignored_routes.append(route)

    # No route found, refund the previous hop so that it can try a new route.
    if try_route is None:
        refund = RefundTransfer(next_state.from_transfer)
        next_state.sent_refund = refund

        next_state.route = None
        next_state.message = None

        iteration = Iteration(next_state, [refund])

    else:
        lock_timeout = (
            next_state.from_transfer.expiration -
            next_state.block_number
        )
        new_lock_timeout = lock_timeout - try_route.reveal_timeout

        # A timeout larger than settle_timeout will be rejected. This /needs/
        # to be validated in state_initialize.
        if new_lock_timeout > try_route.settle_timeout:
            new_lock_timeout = try_route.settle_timeout - try_route.reveal_timeout

        message_id = len(next_state.sent_transfers_refunded)
        new_lock_expiration = new_lock_timeout + next_state.block_number
        mediated_transfer = MediatedTransfer(
            next_state.from_transfer.identifier,
            next_state.from_transfer.lock.token,
            next_state.from_transfer.lock.amount,
            new_lock_expiration,
            next_state.from_transfer.lock.hashlock,
            next_state.from_transfer.target,
            try_route.node_address,
        )
        next_state.message = mediated_transfer

        iteration = Iteration(next_state, [mediated_transfer])

    return iteration


def cancel_current_transfer(next_state):
    cancel_message = CancelMediatedTransfer(next_state.from_transfer)

    next_state.cancel = cancel_message
    next_state.message = None
    next_state.route = None

    iteration = Iteration(next_state, [cancel_message])

    return iteration


def state_transition(current_state, state_change):
    """ State machine for a node mediating a transfer. """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if current_state is None:
        state_uninitialized = True
        state_wait_secret = False
        state_wait_withdraw = False
    else:
        state_uninitialized = False
        state_wait_secret = current_state.message is not None
        state_wait_withdraw = current_state.lock.secret is not None

    iteration = Iteration(current_state, list())
    next_state = deepcopy(current_state)

    if not state_uninitialized:
        if isinstance(state_change, Blocknumber):
            next_state.block_number = state_change.block_number

        elif isinstance(state_change, RouteChange):
            update_route(next_state, state_change)

        elif isinstance(state_change, Cancel):
            iteration = cancel_current_transfer(next_state)

    # Init state and request routes
    if state_uninitialized:
        if isinstance(state_change, InitMediator):
            from_route = state_change.from_route
            lock = state_change.lock
            routes = AvailableRoutesState([
                route
                for route in state_change.routes
                if route.state == 'available'
            ])

            next_state = MediatorState(
                state_change.our_address,
                state_change.target,
                routes,
                state_change.transfer,
                from_route,
                lock,
                state_change.block_number,
            )

            settle_expiration = from_route.settle_timeout + state_change.block_number
            over_settle_expiration = lock.expiration >= settle_expiration

            # The expiration /must/ be lower than settle_timeout, otherwise we
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
                iteration = Iteration(None, list())
            else:
                iteration = try_next_route(next_state)

    elif state_wait_secret:
        valid_refund = (
            isinstance(state_change, RefundTransferReceived) and
            state_change.identifier == state_change.message.identifier and
            state_change.amount == state_change.message.amount and
            state_change.hashlock == state_change.message.hashlock and
            state_change.sender == next_state.message.node_address
        )

        valid_reveal_secret = (
            isinstance(state_change, RevealSecretReceived) and
            sha3(state_change.lock.secret) == next_state.hashlock
        )

        if valid_refund:
            next_state.routes.refund_routes.append(next_state.route)
            next_state.sent_transfers_refunded.append(next_state.message)

            iteration = try_next_route(next_state)

        elif valid_reveal_secret:
            next_state.lock.secret = state_change.lock.secret

            reveal = RevealSecret(
                next_state.transfer.identifier,
                next_state.lock.secret,
                next_state.from_route.node_address,
                next_state.our_address,
            )

            unlocks = [
                UnlockLock(
                    refunded_transfer.identifier,
                    refunded_transfer.node_address,
                    next_state.lock.token,
                    next_state.lock.secret,
                    next_state.hashlock,
                )
                for refunded_transfer in next_state.sent_transfers_refunded
            ]

            iteration = Iteration(next_state, [reveal] + unlocks)

    elif state_wait_withdraw:
        valid_secret = (
            isinstance(state_change, RevealSecretReceived) and
            state_change.sender == next_state.lock.sender
        )

        if valid_secret:
            withdraw = WithdrawLock(
                next_state.transfer.identifier,
                next_state.lock.token,
                next_state.lock.secret,
                next_state.lock.hashlock,
            )
            iteration = Iteration(None, [withdraw])

    return iteration
