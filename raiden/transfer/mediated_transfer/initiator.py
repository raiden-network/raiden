import random

from raiden.constants import MAXIMUM_PENDING_TRANSFERS
from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import EventPaymentSentFailed, EventPaymentSentSuccess
from raiden.transfer.mediated_transfer.events import (
    CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    EventUnlockSuccess,
    SendLockedTransfer,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.state import (
    InitiatorTransferState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveSecretRequest,
    ReceiveSecretReveal,
)
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    NettingChannelState,
    RouteState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal
from raiden.utils import typing


def handle_block(
        initiator_state: InitiatorTransferState,
        state_change: Block,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
) -> TransitionResult:
    secrethash = initiator_state.transfer.lock.secrethash
    locked_lock = channel_state.our_state.secrethashes_to_lockedlocks.get(secrethash)

    lock_expired = channel.is_lock_expired(
        end_state=channel_state.our_state,
        locked_lock=locked_lock,
        secrethash=secrethash,
        block_number=state_change.block_number,
    )
    if locked_lock and lock_expired:
        # Lock has expired, cleanup...
        expired_lock_events = channel.events_for_expired_lock(
            channel_state,
            secrethash,
            locked_lock,
            pseudo_random_generator,
        )

        iteration = TransitionResult(None, expired_lock_events)
        return iteration

    return TransitionResult(initiator_state, list())


def get_initial_lock_expiration(
        block_number: typing.BlockNumber,
        reveal_timeout: typing.BlockTimeout,
) -> typing.BlockExpiration:
    """ Returns the expiration used for all hash-time-locks in transfer. """
    return block_number + reveal_timeout * 2


def next_channel_from_routes(
        available_routes: typing.List[RouteState],
        channelidentifiers_to_channels: typing.ChannelMap,
        transfer_amount: typing.TokenAmount,
) -> typing.Optional[NettingChannelState]:
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

        pending_transfers = channel.get_number_of_pending_transfers(channel_state.our_state)
        if pending_transfers >= MAXIMUM_PENDING_TRANSFERS:
            continue

        distributable = channel.get_distributable(
            channel_state.our_state,
            channel_state.partner_state,
        )
        if transfer_amount > distributable:
            continue

        if channel.is_valid_amount(channel_state.our_state, transfer_amount):
            return channel_state

    return None


def try_new_route(
        channelidentifiers_to_channels: typing.ChannelMap,
        available_routes: typing.List[RouteState],
        transfer_description: TransferDescriptionWithSecretState,
        pseudo_random_generator: random.Random,
        block_number: typing.BlockNumber,
) -> TransitionResult:

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

        transfer_failed = EventPaymentSentFailed(
            payment_network_identifier=transfer_description.payment_network_identifier,
            token_network_identifier=transfer_description.token_network_identifier,
            identifier=transfer_description.payment_identifier,
            target=transfer_description.target,
            reason=reason,
        )
        events.append(transfer_failed)

        initiator_state = None

    else:
        initiator_state = InitiatorTransferState(
            transfer_description,
            channel_state.identifier,
        )

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        lockedtransfer_event = send_lockedtransfer(
            initiator_state,
            channel_state,
            message_identifier,
            block_number,
        )
        assert lockedtransfer_event

        events.append(lockedtransfer_event)

    return TransitionResult(initiator_state, events)


def send_lockedtransfer(
        initiator_state: InitiatorTransferState,
        channel_state: NettingChannelState,
        message_identifier,
        block_number: typing.BlockNumber,
) -> SendLockedTransfer:
    """ Create a mediated transfer using channel.

    Raises:
        AssertionError: If the channel does not have enough capacity.
    """
    transfer_token_address = initiator_state.transfer_description.token_network_identifier
    assert channel_state.token_network_identifier == transfer_token_address

    transfer_description = initiator_state.transfer_description
    lock_expiration = get_initial_lock_expiration(
        block_number,
        channel_state.reveal_timeout,
    )

    lockedtransfer_event = channel.send_lockedtransfer(
        channel_state,
        transfer_description.initiator,
        transfer_description.target,
        transfer_description.amount,
        message_identifier,
        transfer_description.payment_identifier,
        lock_expiration,
        transfer_description.secrethash,
    )
    assert lockedtransfer_event

    initiator_state.transfer = lockedtransfer_event.transfer

    return lockedtransfer_event


def handle_secretrequest(
        initiator_state: InitiatorTransferState,
        state_change: ReceiveSecretRequest,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
) -> TransitionResult:

    is_message_from_target = (
        state_change.sender == initiator_state.transfer_description.target and
        state_change.secrethash == initiator_state.transfer_description.secrethash and
        state_change.payment_identifier == initiator_state.transfer_description.payment_identifier
    )

    lock = channel.get_lock(
        channel_state.our_state,
        initiator_state.transfer_description.secrethash,
    )

    is_valid_secretrequest = (
        is_message_from_target and
        state_change.amount == initiator_state.transfer_description.amount and
        state_change.expiration == lock.expiration
    )

    if is_valid_secretrequest:
        # Reveal the secret to the target node and wait for its confirmation.
        # At this point the transfer is not cancellable anymore as either the lock
        # timeouts or a secret reveal is received.
        #
        # Note: The target might be the first hop
        #
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        transfer_description = initiator_state.transfer_description
        recipient = transfer_description.target
        revealsecret = SendSecretReveal(
            recipient=recipient,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=message_identifier,
            secret=transfer_description.secret,
        )

        initiator_state.revealsecret = revealsecret
        iteration = TransitionResult(initiator_state, [revealsecret])

    elif not is_valid_secretrequest and is_message_from_target:
        cancel = EventPaymentSentFailed(
            payment_network_identifier=channel_state.payment_network_identifier,
            token_network_identifier=channel_state.token_network_identifer,
            identifier=initiator_state.transfer_description.payment_identifier,
            target=initiator_state.transfer_description.target,
            reason='bad secret request message from target',
        )
        iteration = TransitionResult(None, [cancel])

    else:
        iteration = TransitionResult(initiator_state, list())

    return iteration


def handle_secretreveal(
        initiator_state: InitiatorTransferState,
        state_change: ReceiveSecretReveal,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
) -> TransitionResult:
    """ Send a balance proof to the next hop with the current mediated transfer
    lock removed and the balance updated.
    """
    is_valid_secret_reveal = (
        state_change.sender == channel_state.partner_state.address and
        state_change.secrethash == initiator_state.transfer_description.secrethash
    )

    # If the channel is closed the balance proof must not be sent
    is_channel_open = channel.get_status(channel_state) == CHANNEL_STATE_OPENED

    if is_valid_secret_reveal and is_channel_open:
        # next hop learned the secret, unlock the token locally and send the
        # lock claim message to next hop
        transfer_description = initiator_state.transfer_description

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        unlock_lock = channel.send_unlock(
            channel_state=channel_state,
            message_identifier=message_identifier,
            payment_identifier=transfer_description.payment_identifier,
            secret=state_change.secret,
            secrethash=state_change.secrethash,
        )

        # TODO: Emit these events after on-chain unlock
        payment_sent_success = EventPaymentSentSuccess(
            payment_network_identifier=channel_state.payment_network_identifier,
            token_network_identifier=channel_state.token_network_identifier,
            identifier=transfer_description.payment_identifier,
            amount=transfer_description.amount,
            target=transfer_description.target,
        )

        unlock_success = EventUnlockSuccess(
            transfer_description.payment_identifier,
            transfer_description.secrethash,
        )

        iteration = TransitionResult(None, [payment_sent_success, unlock_success, unlock_lock])
    else:
        iteration = TransitionResult(initiator_state, list())

    return iteration


def handle_onchain_secretreveal(
        initiator_state: InitiatorTransferState,
        state_change: ContractReceiveSecretReveal,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
) -> TransitionResult:
    """ Validates and handles a ContractReceiveSecretReveal state change. """
    valid_secret = state_change.secrethash == initiator_state.transfer.lock.secrethash

    iteration = TransitionResult(initiator_state, list())
    if valid_secret:
        # Register LockedTransfer in secrethashes_to_onchain_unlockedlocks
        # without removing the LockedTransfer from secrethashes_to_lockedlocks
        channel.register_onchain_secret(
            channel_state=channel_state,
            secret=state_change.secret,
            secrethash=state_change.secrethash,
            delete_lock=False,
        )
        iteration.new_state = initiator_state

    return iteration
