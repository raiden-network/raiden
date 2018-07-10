from raiden.transfer import channel, secret_registry
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import (
    EventTransferReceivedSuccess,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
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
    ContractReceiveSecretReveal,
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


def events_for_onchain_secretreveal(target_state, channel_state, block_number):
    """ Emits the event for revealing the secret on-chain if the transfer cannot
    to be settled off-chain.
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
        secret = channel.get_secret(
            channel_state.partner_state,
            transfer.lock.secrethash,
        )
        return secret_registry.events_for_onchain_secretreveal(
            channel_state,
            block_number,
            secret,
        )

    return list()


def handle_inittarget(
        state_change,
        channel_state,
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
    is_valid, _, errormsg = channel.handle_receive_lockedtransfer(
        channel_state,
        transfer,
    )

    safe_to_wait = is_safe_to_wait(
        transfer.lock.expiration,
        channel_state.reveal_timeout,
        block_number,
    )

    # if there is not enough time to safely unlock the token on-chain
    # silently let the transfer expire.
    if is_valid and safe_to_wait:
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        recipient = transfer.initiator
        queue_name = b'global'
        secret_request = SendSecretRequest(
            recipient,
            queue_name,
            message_identifier,
            transfer.payment_identifier,
            transfer.lock.amount,
            transfer.lock.secrethash,
        )

        iteration = TransitionResult(target_state, [secret_request])
    else:
        if not is_valid:
            failure_reason = errormsg
        elif not safe_to_wait:
            failure_reason = 'lock expiration is not safe'

        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason=failure_reason,
        )
        iteration = TransitionResult(target_state, [unlock_failed])

    return iteration


def handle_secretreveal(
        target_state,
        state_change,
        channel_state,
        pseudo_random_generator,
):
    """ Validates and handles a ReceiveSecretReveal state change. """
    valid_secret = state_change.secrethash == target_state.transfer.lock.secrethash

    if valid_secret:
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
        queue_name = b'global'
        reveal = SendRevealSecret(
            recipient,
            queue_name,
            message_identifier,
            target_state.secret,
        )

        iteration = TransitionResult(target_state, [reveal])

    else:
        # TODO: event for byzantine behavior
        iteration = TransitionResult(target_state, list())

    return iteration


def handle_unlock(target_state, state_change: ReceiveUnlock, channel_state):
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
            transfer_success = EventTransferReceivedSuccess(
                transfer.payment_identifier,
                transfer.lock.amount,
                transfer.initiator,
            )

            unlock_success = EventUnlockClaimSuccess(
                transfer.payment_identifier,
                transfer.lock.secrethash,
            )

            send_processed = SendProcessed(
                balance_proof_sender,
                b'global',
                state_change.message_identifier,
            )

            events.extend([transfer_success, unlock_success, send_processed])
            iteration = TransitionResult(None, events)

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
        failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason='lock expired',
        )
        target_state.state = 'expired'
        events = [failed]

    elif target_state.state != 'waiting_close':  # only emit the close event once
        events = events_for_onchain_secretreveal(target_state, channel_state, block_number)
    else:
        events = list()

    iteration = TransitionResult(target_state, events)
    return iteration


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

    return iteration
