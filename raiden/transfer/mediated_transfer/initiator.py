import random

from raiden.utils import typing
from raiden.transfer import channel
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockSuccess,
    SendLockedTransfer,
    SendRevealSecret,
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
    message_identifier_from_prng,
    RouteState,
    NettingChannelState,
)

ChannelMap = typing.Dict[typing.ChannelID, NettingChannelState]


def get_initial_lock_expiration(
        block_number: typing.BlockNumber,
        settle_timeout: typing.BlockTimeout,
) -> typing.BlockExpiration:
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


def next_channel_from_routes(
        available_routes: typing.List[RouteState],
        channelidentifiers_to_channels: ChannelMap,
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
        channelidentifiers_to_channels: ChannelMap,
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

        transfer_failed = EventTransferSentFailed(
            identifier=transfer_description.payment_identifier,
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
        channel_state.settle_timeout,
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
        pseudo_random_generator: random.Random,
) -> TransitionResult:

    request_from_target = (
        state_change.sender == initiator_state.transfer_description.target and
        state_change.secrethash == initiator_state.transfer_description.secrethash
    )

    is_valid_payment_id = (
        state_change.payment_identifier == initiator_state.transfer_description.payment_identifier
    )

    valid_secretrequest = (
        request_from_target and
        is_valid_payment_id and
        state_change.amount == initiator_state.transfer_description.amount
    )

    invalid_secretrequest = request_from_target and (
        is_valid_payment_id or
        state_change.amount != initiator_state.transfer_description.amount
    )

    if valid_secretrequest:
        # Reveal the secret to the target node and wait for its confirmation.
        # At this point the transfer is not cancellable anymore as either the lock
        # timeouts or a secret reveal is received.
        #
        # Note: The target might be the first hop
        #
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        transfer_description = initiator_state.transfer_description
        recipient = transfer_description.target
        queue_name = b'global'
        revealsecret = SendRevealSecret(
            recipient,
            queue_name,
            message_identifier,
            transfer_description.secret,
        )

        initiator_state.revealsecret = revealsecret
        iteration = TransitionResult(initiator_state, [revealsecret])

    elif invalid_secretrequest:
        cancel = EventTransferSentFailed(
            identifier=initiator_state.transfer_description.payment_identifier,
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
            channel_state,
            transfer_description.payment_identifier,
            message_identifier,
            state_change.secret,
            state_change.secrethash,
        )

        # TODO: Emit these events after on-chain unlock
        transfer_success = EventTransferSentSuccess(
            transfer_description.payment_identifier,
            transfer_description.amount,
            transfer_description.target,
        )

        unlock_success = EventUnlockSuccess(
            transfer_description.payment_identifier,
            transfer_description.secrethash,
        )

        iteration = TransitionResult(None, [transfer_success, unlock_success, unlock_lock])
    else:
        iteration = TransitionResult(initiator_state, list())

    return iteration
