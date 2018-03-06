# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.mediated_transfer.state import (
    InitiatorState,
    LockedTransferState,
)
from raiden.transfer.mediated_transfer.transition import update_route
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.transfer.state_change import (
    ActionCancelTransfer,
    ActionRouteChange,
    Block,
)
from raiden.transfer.mediated_transfer.state import InitiatorTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionCancelRoute,
    ActionInitInitiator,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof,
    SendMediatedTransfer,
    SendRevealSecret,
    SendRevealSecret2,
)
from raiden.utils import sha3


def get_initial_lock_expiration(block_number, settle_timeout):
    """ Returns the expiration for first hash-time-lock in a mediated transfer. """
    # The initiator doesn't need to learn the secret, so there is no need to
    # decrement reveal_timeout from the settle_timeout.
    #
    # The lock_expiration could be set to a value larger than settle_timeout,
    # this is not useful since the next hop will use the channel settle_timeout
    # as an upper limit for expiration.
    #
    # The two nodes will most likely disagree on the latest block number, as
    # far as the expiration goes this is no problem.
    lock_expiration = block_number + settle_timeout
    return lock_expiration


def next_channel_from_routes(available_routes, channelidentifiers_to_channels, transfer_amount):
    """ Returns the first channel that can be used to start the transfer.
    The routing service can race with local changes, so the recommended routes
    must be validated.
    """
    for route in available_routes:
        channel_identifier = route.channel_identifier
        channel_state = channelidentifiers_to_channels.get(channel_identifier)

        if not channel_state:
            continue

        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            continue

        distributable = channel.get_distributable(
            channel_state.our_state,
            channel_state.partner_state,
        )
        if transfer_amount > distributable:
            continue

        return channel_state


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

    cancel = EventTransferSentFailed(
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

    unlock_failed = None
    if state.message:
        unlock_failed = EventUnlockFailed(
            identifier=state.transfer.identifier,
            hashlock=state.transfer.hashlock,
            reason='route was canceled',
        )

    if try_route is None:
        # No available route has sufficient balance for the current transfer,
        # cancel it.
        #
        # At this point we can just discard all the state data, this is only
        # valid because we are the initiator and we know that the secret was
        # not released.
        transfer_failed = EventTransferSentFailed(
            identifier=state.transfer.identifier,
            reason='no route available',
        )

        events = [transfer_failed]
        if unlock_failed:
            events.append(unlock_failed)
        iteration = TransitionResult(None, events)

    else:
        state.route = try_route

        secret = next(state.random_generator)
        hashlock = sha3(secret)

        # The initiator doesn't need to learn the secret, so there is no need
        # to decrement reveal_timeout from the lock timeout.
        #
        # The lock_expiration could be set to a value larger than
        # settle_timeout, this is not useful since the next hop will take this
        # channel settle_timeout as an upper limit for expiration.
        #
        # The two nodes will most likely disagree on latest block, as far as
        # the expiration goes this is no problem.
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

        events = [message]
        if unlock_failed:
            events.append(unlock_failed)

        iteration = TransitionResult(state, events)

    return iteration


def try_new_route2(
        channelidentifiers_to_channels,
        available_routes,
        transfer_description,
        block_number):

    channel_state = next_channel_from_routes(
        available_routes,
        channelidentifiers_to_channels,
        transfer_description.amount,
    )

    events = list()
    if channel_state is None:
        if not available_routes:
            reason = 'there is no route available'
        else:
            reason = 'none of the available routes could be used'

        transfer_failed = EventTransferSentFailed(
            identifier=transfer_description.identifier,
            reason=reason,
        )
        events.append(transfer_failed)

        initiator_state = None

    else:
        initiator_state = InitiatorTransferState(
            transfer_description,
            channel_state.identifier,
        )

        mediatedtransfer_event = send_mediatedtransfer(
            initiator_state,
            channel_state,
            block_number,
        )
        assert mediatedtransfer_event

        events.append(mediatedtransfer_event)

    return TransitionResult(initiator_state, events)


def send_mediatedtransfer(initiator_state, channel_state, block_number):
    """ Create a mediated transfer using channel.
    Raises:
        AssertionError: If the channel does not have enough capacity.
    """
    assert channel_state.token_address == initiator_state.transfer_description.token

    transfer_description = initiator_state.transfer_description
    lock_expiration = get_initial_lock_expiration(
        block_number,
        channel_state.settle_timeout,
    )

    mediatedtransfer_event = channel.send_mediatedtransfer(
        channel_state,
        transfer_description.initiator,
        transfer_description.target,
        transfer_description.amount,
        transfer_description.identifier,
        lock_expiration,
        transfer_description.hashlock,
    )
    assert mediatedtransfer_event

    initiator_state.transfer = mediatedtransfer_event.transfer

    return mediatedtransfer_event


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
        # Reveal the secret to the target node and wait for its confirmation,
        # at this point the transfer is not cancellable anymore either the lock
        # timeouts or a secret reveal is received.
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


def handle_secretrequest2(initiator_state, state_change):
    request_from_target = (
        state_change.sender == initiator_state.transfer_description.target and
        state_change.hashlock == initiator_state.transfer_description.hashlock
    )

    valid_secretrequest = (
        request_from_target and
        state_change.identifier == initiator_state.transfer_description.identifier and
        state_change.amount == initiator_state.transfer_description.amount
    )

    invalid_secretrequest = request_from_target and (
        state_change.identifier != initiator_state.transfer_description.identifier or
        state_change.amount != initiator_state.transfer_description.amount
    )

    if valid_secretrequest:
        # Reveal the secret to the target node and wait for its confirmation.
        # At this point the transfer is not cancellable anymore as either the lock
        # timeouts or a secret reveal is received.
        #
        # Note: The target might be the first hop
        #
        transfer_description = initiator_state.transfer_description
        reveal_secret = SendRevealSecret2(
            transfer_description.identifier,
            transfer_description.secret,
            transfer_description.token,
            transfer_description.target,
        )

        initiator_state.revealsecret = reveal_secret
        iteration = TransitionResult(initiator_state, [reveal_secret])

    elif invalid_secretrequest:
        cancel = EventTransferSentFailed(
            identifier=initiator_state.transfer_description.identifier,
            reason='bad secret request message from target',
        )
        iteration = TransitionResult(None, [cancel])

    else:
        iteration = TransitionResult(initiator_state, list())

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

        transfer_success = EventTransferSentSuccess(
            transfer.identifier,
            transfer.amount,
            transfer.target,
        )

        unlock_success = EventUnlockSuccess(
            transfer.identifier,
            transfer.hashlock,
        )

        iteration = TransitionResult(None, [unlock_lock, transfer_success, unlock_success])
    else:
        iteration = TransitionResult(state, list())

    return iteration


def handle_secretreveal2(initiator_state, state_change, channel_state):
    """ Send a balance proof to the next hop with the current mediated transfer
    lock removed and the balance updated.
    """
    is_valid_secret_reveal = (
        state_change.sender == channel_state.partner_state.address and
        state_change.hashlock == initiator_state.transfer_description.hashlock
    )

    # If the channel is closed the balance proof must not be sent
    is_channel_open = channel.get_status(channel_state) == CHANNEL_STATE_OPENED

    if is_valid_secret_reveal and is_channel_open:
        # next hop learned the secret, unlock the token locally and send the
        # withdraw message to next hop
        transfer_description = initiator_state.transfer_description

        unlock_lock = channel.send_unlock(
            channel_state,
            transfer_description.identifier,
            state_change.secret,
            state_change.hashlock,
        )

        # TODO: Emit these events after on-chain withdraw
        transfer_success = EventTransferSentSuccess(
            transfer_description.identifier,
            transfer_description.amount,
            transfer_description.target,
        )

        unlock_success = EventUnlockSuccess(
            transfer_description.identifier,
            transfer_description.hashlock,
        )

        iteration = TransitionResult(None, [transfer_success, unlock_success, unlock_lock])
    else:
        iteration = TransitionResult(initiator_state, list())

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
