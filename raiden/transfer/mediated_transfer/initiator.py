# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import TransitionResult
from raiden.transfer.mediated_transfer.state import (
    InitiatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.state_change import (
    ActionCancelTransfer,
    ActionRouteChange,
    Block,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionCancelRoute,
    ActionInitInitiator,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.mediated_transfer.events import (
    EventTransferCompleted,
    EventTransferFailed,
    SendBalanceProof,
    SendMediatedTransfer,
    SendRevealSecret,
)
from raiden.utils import sha3


def cancel_current_route(state):
    """ Clear current state and try a new route.

    - Discards the current secret
    - Add the current route to the canceled list
    - Add the current message to the canceled transfers
    """
    assert state.revealsecret is None, 'cannot cancel a transfer with a RevealSecret in flight'

    state.routes.canceled_routes.append(state.route)
    state.canceled_transfers.append(state.message)

    state.transfer.secret = None
    state.transfer.hashlock = None
    state.message = None
    state.route = None
    state.secretrequest = None

    return try_new_route(state)


def user_cancel_transfer(state):
    """ Cancel the current in-transit message. """
    assert state.revealsecret is None, 'cannot cancel a transfer with a RevealSecret in flight'

    state.transfer.secret = None
    state.transfer.hashlock = None
    state.message = None
    state.route = None
    state.secretrequest = None
    state.revealsecret = None

    cancel = EventTransferFailed(
        identifier=state.transfer.identifier,
        reason='user canceled transfer',
    )
    iteration = TransitionResult(None, [cancel])

    return iteration


def try_new_route(state):
    assert state.route is None, 'cannot try a new route while one is being used'

    # TODO:
    # - Route ranking. An upper layer should rate each route to optimize
    #   the fee price/quality of each route and add a rate from in the range
    #   [0.0,1.0].
    # - Add in a policy per route:
    #   - filtering, e.g. so the user may have a per route maximum transfer
    #     value based on fixed value or reputation.
    #   - reveal time computation
    #   - These policy details are better hidden from this implementation and
    #     changes should be applied through the use of Route state changes.

    # Find a single route that may fulfill the request, this uses a single
    # route intentionally
    try_route = None
    while state.routes.available_routes:
        route = state.routes.available_routes.pop(0)

        if route.available_balance < state.transfer.amount:
            state.routes.ignored_routes.append(route)
        else:
            try_route = route
            break

    if try_route is None:
        # No available route has sufficient balance for the current transfer,
        # cancel it.
        #
        # At this point we can just discard all the state data, this is only
        # valid because we are the initiator and we know that the secret was
        # not released.
        cancel = EventTransferFailed(
            identifier=state.transfer.identifier,
            reason='no route available',
        )
        iteration = TransitionResult(None, [cancel])

    else:
        state.route = try_route

        secret = state.random_generator.next()
        hashlock = sha3(secret)

        # The initiator doesn't need to learn the secret, so there is no need
        # to decrement reveal_timeout from the lock timeout.
        #
        # A value larger than settle_timeout could be used but wouldn't
        # improve, since the next hop will take settle_timeout as an upper
        # limit for expiration.
        lock_expiration = state.block_number + try_route.settle_timeout
        identifier = state.transfer.identifier

        transfer = LockedTransferState(
            identifier,
            state.transfer.amount,
            state.transfer.token,
            state.transfer.initiator,
            state.transfer.target,
            lock_expiration,
            hashlock,
            secret,
        )

        message = SendMediatedTransfer(
            transfer.identifier,
            transfer.token,
            transfer.amount,
            transfer.hashlock,
            state.our_address,
            transfer.target,
            lock_expiration,
            try_route.node_address,
        )

        state.transfer = transfer
        state.message = message

        iteration = TransitionResult(state, [message])

    return iteration


def handle_block(state, state_change):
    state.block_number = max(
        state.block_number,
        state_change.block_number,
    )
    iteration = TransitionResult(state, list())
    return iteration


def handle_routechange(state, state_change):
    update_route(state, state_change)
    iteration = TransitionResult(state, list())
    return iteration


def handle_transferrefund(state, state_change):
    if state_change.sender == state.route.node_address:
        iteration = cancel_current_route(state)
    else:
        iteration = TransitionResult(state, list())

    return iteration


def handle_cancelroute(state, state_change):
    if state_change.identifier == state.transfer.identifier:
        iteration = cancel_current_route(state)
    else:
        iteration = TransitionResult(state, list())

    return iteration


def handle_canceltransfer(state):
    iteration = user_cancel_transfer(state)
    return iteration


def handle_secretrequest(state, state_change):
    valid_secretrequest = (
        state_change.sender == state.transfer.target and
        state_change.hashlock == state.transfer.hashlock and
        state_change.identifier == state.transfer.identifier and
        state_change.amount == state.transfer.amount
    )

    invalid_secretrequest = (
        state_change.sender == state.transfer.target and
        state_change.hashlock == state.transfer.hashlock and

        not valid_secretrequest
    )

    if valid_secretrequest:
        # Reveal the secret to the target node and wait for it's confirmation,
        # at this point the transfer is not cancellable anymore.
        #
        # Note: The target might be the first hop
        #
        transfer = state.transfer
        reveal_secret = SendRevealSecret(
            transfer.identifier,
            transfer.secret,
            transfer.token,
            transfer.target,
            state.our_address,
        )

        state.revealsecret = reveal_secret
        iteration = TransitionResult(state, [reveal_secret])

    elif invalid_secretrequest:
        iteration = cancel_current_route(state)

    else:
        iteration = TransitionResult(state, list())

    return iteration


def handle_secretreveal(state, state_change):
    """ Send a balance proof to the next hop with the current mediated transfer
    lock removed and the balance updated.
    """
    if state_change.sender == state.route.node_address:
        # next hop learned the secret, unlock the token locally and send the
        # withdraw message to next hop
        transfer = state.transfer
        unlock_lock = SendBalanceProof(
            transfer.identifier,
            state.route.channel_address,
            transfer.token,
            state.route.node_address,
            transfer.secret,
        )

        completed = EventTransferCompleted(
            transfer.identifier,
            transfer.secret,
            transfer.hashlock,
        )

        iteration = TransitionResult(None, [unlock_lock, completed])
    else:
        iteration = TransitionResult(state, list())

    return iteration


def state_transition(state, state_change):
    """ State machine for a node starting a mediated transfer.

    Args:
        state: The current State that is transitioned from.
        state_change: The state_change that will be applied.
    """

    # TODO: Add synchronization for expired locks.
    # Transfers added to the canceled list by an ActionCancelRoute are stale in
    # the channels merkle tree, while this doesn't increase the messages sizes
    # nor does it interfere with the guarantees of finality it increases memory
    # usage for each end, since the full merkle tree must be saved to compute
    # it's root.

    iteration = TransitionResult(state, list())

    if state is None:
        if isinstance(state_change, ActionInitInitiator):
            routes = deepcopy(state_change.routes)

            state = InitiatorState(
                state_change.our_address,
                state_change.transfer,
                routes,
                state_change.block_number,
                state_change.random_generator,
            )

            iteration = try_new_route(state)

    elif state.revealsecret is None:
        if isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

        elif isinstance(state_change, ActionRouteChange):
            iteration = handle_routechange(state, state_change)

        elif isinstance(state_change, ReceiveSecretRequest):
            iteration = handle_secretrequest(state, state_change)

        elif isinstance(state_change, ReceiveTransferRefund):
            iteration = handle_transferrefund(state, state_change)

        elif isinstance(state_change, ActionCancelRoute):
            iteration = handle_cancelroute(state, state_change)

        elif isinstance(state_change, ActionCancelTransfer):
            iteration = handle_canceltransfer(state)

    elif state.revealsecret is not None:
        if isinstance(state_change, Block):
            iteration = handle_block(state, state_change)

        elif isinstance(state_change, ReceiveSecretReveal):
            iteration = handle_secretreveal(state, state_change)

    return iteration
