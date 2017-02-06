# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import Iteration
from raiden.transfer.state import RoutesState
from raiden.transfer.mediated_transfer.state import (
    InitiatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.state_change import (
    # blockchain events
    Blocknumber,
    RouteChange,
    # user interaction
    CancelTransfer,
)
from raiden.transfer.mediated_transfer.state_change import (
    # machine state
    InitInitiator,
    # protocol messages
    TransferRefundReceived,
    SecretRequestReceived,
    SecretRevealReceived,
    # user interaction
    CancelRoute,
)
from raiden.transfer.mediated_transfer.events import (
    TransferFailed,
    MediatedTransfer,
    RevealSecretTo,
)
from raiden.utils import sha3


def cancel_current_route(next_state):
    """ Clear current state and try a new rotue.

    - Discards the current secret
    - Add the current route to the canceled list
    - Add the current message to the canceled transfers
    """
    assert next_state.revealsecret is None, 'cannot cancel a transfer with a RevealSecret in flight'

    next_state.routes.canceled_routes.append(next_state.route)
    next_state.canceled_transfers.append(next_state.message)

    next_state.transfer.secret = None
    next_state.transfer.hashlock = None
    next_state.message = None
    next_state.route = None
    next_state.secretrequest = None

    return try_new_route(next_state)


def user_cancel_transfer(next_state):
    """ Cancel the current in-transit message. """
    assert next_state.revealsecret is None, 'cannot cancel a transfer with a RevealSecret in flight'

    # reset the next_state copy
    next_state.transfer.secret = None
    next_state.transfer.hashlock = None
    next_state.message = None
    next_state.route = None
    next_state.secretrequest = None
    next_state.revealsecret = None

    cancel = TransferFailed(
        identifier=next_state.transfer.identifier,
        reason='user canceled transfer',
    )
    iteration = Iteration(None, [cancel])

    return iteration


def try_new_route(next_state):
    assert next_state.route is None, 'cannot try a new route while one is being used'

    # TODO:
    # - Route ranking. An upper layer should rate each route to optimize
    #   the fee price/quality of each route and add a rate from in the range
    #   [0.0,1.0].
    # - Add in the policy a per route:
    #   - filtering, e.g. so the user may have a per route maximum transfer
    #     value based on fixed value or reputation.
    #   - reveal time computation
    #   - These policy details are better hidden from this implementation and
    #     chanages should be applied though the use of Route state changes.

    # Find a single route that may fulfill the request, this uses a single
    # route intentionally
    try_route = None
    while next_state.routes.available_routes:
        route = next_state.routes.available_routes.pop(0)

        if route.available_balance < next_state.transfer.amount:
            next_state.routes.ignored_routes.append(route)
        else:
            try_route = route
            break

    if try_route is None:
        # No avaiable route has sufficient balance for the current transfer,
        # cancel it.
        #
        # At this point we can just discard all the state data, this is only
        # valid because we are the initiator and we known that the secret was
        # not released.
        cancel = TransferFailed(
            identifier=next_state.transfer.identifier,
            reason='no route available',
        )
        iteration = Iteration(None, [cancel])

    else:
        next_state.route = try_route

        secret = next_state.random_generator.next()
        hashlock = sha3(secret)

        # The initiator doesn't need to learn the secret, so there is no need
        # to decremented reveal_timeout from the lock timeout.
        #
        # A value larger than settle_timeout could be used but wouldn't
        # improve, since the next hop will take settle_timeout as an upper
        # limit for expiration.
        lock_expiration = next_state.block_number + try_route.settle_timeout
        identifier = next_state.transfer.identifier

        transfer = LockedTransferState(
            identifier,
            next_state.transfer.amount,
            next_state.transfer.token,
            next_state.transfer.target,
            lock_expiration,
            hashlock,
            secret,
        )

        message = MediatedTransfer(
            transfer.identifier,
            transfer.token,
            transfer.amount,
            transfer.hashlock,
            transfer.target,
            lock_expiration,
            try_route.node_address,
        )

        next_state.transfer = transfer
        next_state.message = message

        iteration = Iteration(next_state, [message])

    return iteration


def state_transition(state, state_change):
    """ State machine for a node starting a mediated transfer.
    Args:
        state: the current State that is transitioned from
        state_change: the state_change that will be applied
    """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if state is None:
        state_uninitialized = True
        state_wait_secretrequest = False
        state_wait_unlock = False
    else:
        state_uninitialized = False
        state_wait_secretrequest = state.revealsecret is None
        state_wait_unlock = state.revealsecret is not None

    iteration = Iteration(state, list())

    if not state_uninitialized:
        if isinstance(state_change, Blocknumber):
            state.block_number = state_change.block_number

        elif isinstance(state_change, RouteChange):
            update_route(state, state_change)

    # Init state and try the first available route
    if state_uninitialized:
        if isinstance(state_change, InitInitiator):
            # assumes this is a clean RoutesState
            assert isinstance(state_change.routes, RoutesState)
            routes = deepcopy(state_change.routes)

            state = InitiatorState(
                state_change.our_address,
                state_change.transfer,
                routes,
                state_change.block_number,
                state_change.random_generator,
            )

            iteration = try_new_route(state)

    # 1- Target received the mediated transfer and sent a secretrequest.
    # 2- The mediated transfer failed mid flight and we need to try a new route.
    elif state_wait_secretrequest:

        if isinstance(state_change, SecretRequestReceived):
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
        else:
            valid_secretrequest = False
            invalid_secretrequest = False

        # The initiator does not care if the TransferRefundReceived has a valid
        # hashlock and amount since the current secret will be discarded
        refund_transfer = (
            isinstance(state_change, TransferRefundReceived) and
            state_change.sender == state.route.node_address
        )

        cancel_transfer = (
            isinstance(state_change, CancelRoute) and
            state_change.identifier == state.transfer.identifier
        )

        if valid_secretrequest:
            # Reveal the secret to the target node and wait for it's
            # confirmation, at this point the transfer is not cancellable
            # anymore.
            #
            # Note: The target might be the first hop
            #
            reveal_secret = RevealSecretTo(
                state.transfer.identifier,
                state.transfer.secret,
                state.transfer.target,
                state.our_address,
            )

            state.revealsecret = reveal_secret
            iteration = Iteration(state, [reveal_secret])

        elif invalid_secretrequest or refund_transfer or cancel_transfer:
            # anything out-of-the-ordinary happened
            iteration = cancel_current_route(state)

        elif isinstance(state_change, CancelTransfer):
            # the raiden user (could be another software) asked for the
            # transfer to be canceled
            iteration = user_cancel_transfer(state)

    elif state_wait_unlock:

        secret_reveal = (
            isinstance(state_change, SecretRevealReceived) and
            state_change.sender == state.route.node_address
        )

        if secret_reveal:
            # next hop learned the secret, unlock the token locally and send
            # the withdraw message to next hop
            unlock_lock = RevealSecretTo(
                state.transfer.identifier,
                state.secret,
                state.route.node_address,
                state.our_address,
            )

            iteration = Iteration(None, [unlock_lock])

    return iteration
