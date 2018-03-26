# -*- coding: utf-8 -*-
from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.transfer.mediated_transfer.state import InitiatorTransferState
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockSuccess,
    SendRevealSecret2,
)


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
