# -*- coding: utf-8 -*-
from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import EventTransferReceivedSuccess
from raiden.transfer.mediated_transfer.events import (
    EventWithdrawFailed,
    EventWithdrawSuccess,
    SendRevealSecret,
    SendSecretRequest,
)
from raiden.transfer.mediated_transfer.mediator import is_safe_to_wait
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
    ReceiveSecretReveal,
)
from raiden.transfer.state import message_identifier_from_prng
from raiden.transfer.state_change import (
    Block,
    ReceiveUnlock,
)


def events_for_close(target_state, channel_state, block_number):
    """ Emits the event for closing the netting channel if the transfer needs
    to be settled on-chain.
    """
    transfer = target_state.transfer

    safe_to_wait = is_safe_to_wait(
        transfer.lock.expiration,
        channel_state.reveal_timeout,
        block_number,
    )
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.secrethash,
    )

    if not safe_to_wait and secret_known:
        target_state.state = 'waiting_close'
        return channel.events_for_close(channel_state, block_number)

    return list()


def handle_inittarget(
        state_change,
        channel_state,
        queueids_to_queues,
        pseudo_random_generator,
        block_number,
):
    """ Handles an ActionInitTarget state change. """
    transfer = state_change.transfer
    route = state_change.route

    target_state = TargetTransferState(
        route,
        transfer,
    )

    assert channel_state.identifier == transfer.balance_proof.channel_address
    is_valid, errormsg = channel.handle_receive_lockedtransfer(
        channel_state,
        transfer,
    )

    safe_to_wait = is_safe_to_wait(
        transfer.lock.expiration,
        channel_state.reveal_timeout,
        block_number,
    )

    # if there is not enough time to safely withdraw the token on-chain
    # silently let the transfer expire.
    if is_valid and safe_to_wait:
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        secret_request = SendSecretRequest(
            message_identifier,
            transfer.payment_identifier,
            transfer.lock.amount,
            transfer.lock.secrethash,
            transfer.initiator,
        )

        queueid = (route.node_address, 'global')
        partner_default_message_queue = queueids_to_queues.setdefault(queueid, [])
        partner_default_message_queue.append(secret_request)
        iteration = TransitionResult(target_state, [secret_request])
    else:
        if not is_valid:
            failure_reason = errormsg
        elif not safe_to_wait:
            failure_reason = 'lock expiration is not safe'

        withdraw_failed = EventWithdrawFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason=failure_reason,
        )
        iteration = TransitionResult(target_state, [withdraw_failed])

    return iteration


def handle_secretreveal(
        target_state,
        state_change,
        channel_state,
        queueids_to_queues,
        pseudo_random_generator,
):
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = state_change.secrethash == target_state.transfer.lock.secrethash

    if valid_secret:
        channel.register_secret(
            channel_state,
            state_change.secret,
            state_change.secrethash,
        )

        transfer = target_state.transfer
        route = target_state.route

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        target_state.state = 'reveal_secret'
        target_state.secret = state_change.secret
        receiver_address = route.node_address
        reveal = SendRevealSecret(
            message_identifier,
            target_state.secret,
            transfer.token,
            receiver_address,
        )

        queueid = (receiver_address, 'global')
        partner_default_message_queue = queueids_to_queues.setdefault(queueid, [])
        partner_default_message_queue.append(reveal)

        iteration = TransitionResult(target_state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_unlock(target_state, state_change, channel_state):
    """ Handles a ReceiveUnlock state change. """
    iteration = TransitionResult(target_state, list())

    if state_change.balance_proof.sender == target_state.route.node_address:
        is_valid, _ = channel.handle_unlock(
            channel_state,
            state_change,
        )

        if is_valid:
            transfer = target_state.transfer
            transfer_success = EventTransferReceivedSuccess(
                transfer.payment_identifier,
                transfer.lock.amount,
                transfer.initiator,
            )

            unlock_success = EventWithdrawSuccess(
                transfer.payment_identifier,
                transfer.lock.secrethash,
            )

            iteration = TransitionResult(None, [transfer_success, unlock_success])

    return iteration


def handle_block(target_state, channel_state, block_number):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time lock.
    """
    transfer = target_state.transfer
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.secrethash,
    )

    if not secret_known and block_number > transfer.lock.expiration:
        # XXX: emit the event only once
        failed = EventWithdrawFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason='lock expired',
        )
        target_state.state = 'expired'
        events = [failed]

    elif target_state.state != 'waiting_close':  # only emit the close event once
        events = events_for_close(target_state, channel_state, block_number)
    else:
        events = list()

    iteration = TransitionResult(target_state, events)
    return iteration


def state_transition(
        target_state,
        state_change,
        channel_state,
        queueids_to_queues,
        pseudo_random_generator,
        block_number,
):
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    iteration = TransitionResult(target_state, list())

    if type(state_change) == ActionInitTarget:
        iteration = handle_inittarget(
            state_change,
            channel_state,
            queueids_to_queues,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == Block:
        assert state_change.block_number == block_number

        iteration = handle_block(
            target_state,
            channel_state,
            state_change.block_number,
        )
    elif type(state_change) == ReceiveSecretReveal:
        iteration = handle_secretreveal(
            target_state,
            state_change,
            channel_state,
            queueids_to_queues,
            pseudo_random_generator,
        )
    elif type(state_change) == ReceiveUnlock:
        iteration = handle_unlock(
            target_state,
            state_change,
            channel_state,
        )

    return iteration
