# -*- coding: utf-8 -*-
from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.state_change import (
    Block,
    ReceiveUnlock,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget2,
    ReceiveSecretReveal,
)
from raiden.transfer.events import (
    EventTransferReceivedSuccess,
)
from raiden.transfer.mediated_transfer.events import (
    EventWithdrawFailed,
    EventWithdrawSuccess,
    SendRevealSecret2,
    SendSecretRequest,
)
from raiden.transfer.mediated_transfer.mediator import is_safe_to_wait2


def events_for_close2(target_state, channel_state, block_number):
    """ Emits the event for closing the netting channel if the transfer needs
    to be settled on-chain.
    """
    transfer = target_state.transfer

    safe_to_wait = is_safe_to_wait2(
        transfer.lock.expiration,
        channel_state.reveal_timeout,
        block_number,
    )
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.hashlock,
    )

    if not safe_to_wait and secret_known:
        target_state.state = 'waiting_close'
        return channel.events_for_close(channel_state, block_number)

    return list()


def handle_inittarget2(state_change, channel_state, block_number):
    """ Handles an ActionInitTarget2 state change. """
    transfer = state_change.transfer
    route = state_change.route

    target_state = TargetTransferState(
        route,
        transfer,
    )

    assert channel_state.identifier == transfer.balance_proof.channel_address
    is_valid, _ = channel.handle_receive_mediatedtransfer(
        channel_state,
        transfer,
    )

    safe_to_wait = is_safe_to_wait2(
        transfer.lock.expiration,
        channel_state.reveal_timeout,
        block_number,
    )

    # if there is not enough time to safely withdraw the token on-chain
    # silently let the transfer expire.
    if is_valid and safe_to_wait:
        secret_request = SendSecretRequest(
            transfer.identifier,
            transfer.lock.amount,
            transfer.lock.hashlock,
            transfer.initiator,
        )

        iteration = TransitionResult(target_state, [secret_request])
    else:
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_secretreveal2(target_state, state_change, channel_state):
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = state_change.hashlock == target_state.transfer.lock.hashlock

    if valid_secret:
        channel.register_secret(
            channel_state,
            state_change.secret,
            state_change.hashlock,
        )

        transfer = target_state.transfer
        route = target_state.route

        target_state.state = 'reveal_secret'
        target_state.secret = state_change.secret
        reveal = SendRevealSecret2(
            transfer.identifier,
            target_state.secret,
            transfer.token,
            route.node_address,
        )

        iteration = TransitionResult(target_state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_unlock(target_state, state_change, channel_state):
    """ Handles a ReceiveBalanceProof state change. """
    iteration = TransitionResult(target_state, list())

    if state_change.balance_proof.sender == target_state.route.node_address:
        is_valid, _ = channel.handle_unlock(
            channel_state,
            state_change,
        )

        if is_valid:
            transfer = target_state.transfer
            transfer_success = EventTransferReceivedSuccess(
                transfer.identifier,
                transfer.lock.amount,
                transfer.initiator,
            )

            unlock_success = EventWithdrawSuccess(
                transfer.identifier,
                transfer.lock.hashlock,
            )

            iteration = TransitionResult(None, [transfer_success, unlock_success])

    return iteration


def handle_block2(target_state, channel_state, block_number):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time lock.
    """
    transfer = target_state.transfer
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.hashlock,
    )

    if not secret_known and block_number > transfer.lock.expiration:
        # XXX: emit the event only once
        failed = EventWithdrawFailed(
            identifier=transfer.identifier,
            hashlock=transfer.lock.hashlock,
            reason='lock expired',
        )
        target_state.state = 'expired'
        events = [failed]

    elif target_state.state != 'waiting_close':  # only emit the close event once
        events = events_for_close2(target_state, channel_state, block_number)
    else:
        events = list()

    iteration = TransitionResult(target_state, events)
    return iteration


def state_transition2(target_state, state_change, channel_state, block_number):
    """ State machine for the target node of a mediated transfer. """
    iteration = TransitionResult(target_state, list())

    if isinstance(state_change, ActionInitTarget2):
        iteration = handle_inittarget2(
            state_change,
            channel_state,
            block_number,
        )
    elif isinstance(state_change, Block):
        assert state_change.block_number == block_number

        iteration = handle_block2(
            target_state,
            channel_state,
            state_change.block_number,
        )
    elif isinstance(state_change, ReceiveSecretReveal):
        iteration = handle_secretreveal2(
            target_state,
            state_change,
            channel_state,
        )
    elif isinstance(state_change, ReceiveUnlock):
        iteration = handle_unlock(
            target_state,
            state_change,
            channel_state,
        )

    return iteration
