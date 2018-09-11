import random

from raiden.transfer import channel, secret_registry
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import EventPaymentReceivedSuccess, SendProcessed
from raiden.transfer.mediated_transfer.events import (
    CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    SendSecretRequest,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.mediator import is_safe_to_wait
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveSecretReveal,
)
from raiden.transfer.state import NettingChannelState, message_identifier_from_prng
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal, ReceiveUnlock
from raiden.utils import typing


def events_for_close(
        target_state: TargetTransferState,
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
):
    """ Emits the event for closing the netting channel if the transfer needs
    to be settled on-chain.
    """
    transfer = target_state.transfer

    safe_to_wait, _ = is_safe_to_wait(
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


def events_for_onchain_secretreveal(
        target_state: TargetTransferState,
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
):
    """ Emits the event for revealing the secret on-chain if the transfer cannot
    to be settled off-chain.
    """
    transfer = target_state.transfer
    expiration = transfer.lock.expiration

    safe_to_wait, _ = is_safe_to_wait(
        expiration,
        channel_state.reveal_timeout,
        block_number,
    )
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.secrethash,
    )

    if not safe_to_wait and secret_known:
        secret = channel.get_secret(
            channel_state.partner_state,
            transfer.lock.secrethash,
        )
        return secret_registry.events_for_onchain_secretreveal(
            channel_state,
            secret,
            expiration,
        )

    return list()


def handle_inittarget(
        state_change: ActionInitTarget,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
        block_number: typing.BlockNumber,
):
    """ Handles an ActionInitTarget state change. """
    transfer = state_change.transfer
    route = state_change.route

    assert channel_state.identifier == transfer.balance_proof.channel_identifier
    is_valid, channel_events, errormsg = channel.handle_receive_lockedtransfer(
        channel_state,
        transfer,
    )

    if is_valid:
        # A valid balance proof does not mean the payment itself is still valid.
        # e.g. the lock may be near expiration or have expired. This is fine. The
        # message with an unusable lock must be handled to properly synchronize the
        # local view of the partner's channel state, allowing the next balance
        # proofs to be handled. This however, must only be done once, which is
        # enforced by the nonce increasing sequentially, which is verified by
        # the handler handle_receive_lockedtransfer.
        target_state = TargetTransferState(route, transfer)

        safe_to_wait, unsafe_msg = is_safe_to_wait(
            transfer.lock.expiration,
            channel_state.reveal_timeout,
            block_number,
        )

        if safe_to_wait:
            message_identifier = message_identifier_from_prng(pseudo_random_generator)
            recipient = transfer.initiator
            secret_request = SendSecretRequest(
                recipient=recipient,
                channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
                message_identifier=message_identifier,
                payment_identifier=transfer.payment_identifier,
                amount=transfer.lock.amount,
                expiration=transfer.lock.expiration,
                secrethash=transfer.lock.secrethash,
            )
            channel_events.append(secret_request)
        else:
            # If there is not enough time to safely unlock the lock on-chain
            # silently let the transfer expire. The target task must be created
            # to handle the ReceiveLockExpired state change, which will clear
            # the expired lock.
            unlock_failed = EventUnlockClaimFailed(
                identifier=transfer.payment_identifier,
                secrethash=transfer.lock.secrethash,
                reason=unsafe_msg,
            )
            channel_events.append(unlock_failed)

        iteration = TransitionResult(target_state, channel_events)
    else:
        # If the balance proof is not valid, do *not* create a task. Otherwise it's
        # possible for an attacker to send multiple invalid transfers, and increase
        # the memory usage of this Node.
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason=errormsg,
        )
        channel_events.append(unlock_failed)
        iteration = TransitionResult(None, channel_events)

    return iteration


def handle_secretreveal(
        target_state: TargetTransferState,
        state_change: ReceiveSecretReveal,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
):
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = state_change.secrethash == target_state.transfer.lock.secrethash
    waiting_for_secret = target_state.state == 'secret_request'

    if valid_secret and waiting_for_secret:
        if isinstance(state_change, ReceiveSecretReveal):
            channel.register_secret(
                channel_state,
                state_change.secret,
                state_change.secrethash,
            )
        elif isinstance(state_change, ContractReceiveSecretReveal):
            channel.register_onchain_secret(
                channel_state,
                state_change.secret,
                state_change.secrethash,
            )
        else:
            assert False, 'Got unexpected StateChange'

        route = target_state.route
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        target_state.state = 'reveal_secret'
        target_state.secret = state_change.secret
        recipient = route.node_address

        # Send the secret reveal message only once, delivery is guaranteed by
        # the transport and not by the state machine
        reveal = SendSecretReveal(
            recipient=recipient,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=message_identifier,
            secret=target_state.secret,
        )

        iteration = TransitionResult(target_state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_unlock(
        target_state: TargetTransferState,
        state_change: ReceiveUnlock,
        channel_state: NettingChannelState,
):
    """ Handles a ReceiveUnlock state change. """
    iteration = TransitionResult(target_state, list())
    balance_proof_sender = state_change.balance_proof.sender

    if balance_proof_sender == target_state.route.node_address:
        is_valid, events, _ = channel.handle_unlock(
            channel_state,
            state_change,
        )

        if is_valid:
            transfer = target_state.transfer
            payment_received_success = EventPaymentReceivedSuccess(
                payment_network_identifier=channel_state.payment_network_identifier,
                token_network_identifier=channel_state.token_network_identifier,
                identifier=transfer.payment_identifier,
                amount=transfer.lock.amount,
                initiator=transfer.initiator,
            )

            unlock_success = EventUnlockClaimSuccess(
                transfer.payment_identifier,
                transfer.lock.secrethash,
            )

            send_processed = SendProcessed(
                recipient=balance_proof_sender,
                channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
                message_identifier=state_change.message_identifier,
            )

            events.extend([payment_received_success, unlock_success, send_processed])
            iteration = TransitionResult(None, events)

    return iteration


def handle_block(
        target_state: TargetTransferState,
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
        pseudo_random_generator: random.Random,
):
    """ After Raiden learns about a new block this function must be called to
    handle expiration of the hash time lock.
    """
    transfer = target_state.transfer
    secret_known = channel.is_secret_known(
        channel_state.partner_state,
        transfer.lock.secrethash,
    )

    if not secret_known and block_number > transfer.lock.expiration:
        if target_state.state != 'expired':
            failed = EventUnlockClaimFailed(
                identifier=transfer.payment_identifier,
                secrethash=transfer.lock.secrethash,
                reason='lock expired',
            )
            target_state.state = 'expired'
            events = [failed]
        else:
            events = list()
    elif target_state.state != 'waiting_close':  # only emit the close event once
        events = events_for_onchain_secretreveal(target_state, channel_state, block_number)
    else:
        events = list()

    iteration = TransitionResult(target_state, events)
    return iteration


def handle_lock_expired(
        target_state: TargetTransferState,
        state_change: ReceiveLockExpired,
        channel_state: NettingChannelState,
):
    """Remove expired locks from channel states."""
    result = channel.handle_receive_lock_expired(channel_state, state_change)
    if not channel.get_lock(result.new_state.partner_state, target_state.transfer.lock.secrethash):
        return TransitionResult(None, result.events)

    return TransitionResult(target_state, result.events)


def state_transition(
        target_state,
        state_change,
        channel_state,
        pseudo_random_generator,
        block_number,
):
    """ State machine for the target node of a mediated transfer. """
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    iteration = TransitionResult(target_state, list())
    if type(state_change) == ActionInitTarget:
        if target_state is None:
            iteration = handle_inittarget(
                state_change,
                channel_state,
                pseudo_random_generator,
                block_number,
            )
    elif type(state_change) == Block:
        assert state_change.block_number == block_number

        iteration = handle_block(
            target_state,
            channel_state,
            state_change.block_number,
            pseudo_random_generator,
        )
    elif type(state_change) == ReceiveSecretReveal:
        iteration = handle_secretreveal(
            target_state,
            state_change,
            channel_state,
            pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        iteration = handle_secretreveal(
            target_state,
            state_change,
            channel_state,
            pseudo_random_generator,
        )
    elif type(state_change) == ReceiveUnlock:
        iteration = handle_unlock(
            target_state,
            state_change,
            channel_state,
        )
    elif type(state_change) == ReceiveLockExpired:
        iteration = handle_lock_expired(
            target_state,
            state_change,
            channel_state,
        )

    return iteration
