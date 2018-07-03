import random

from raiden.utils import typing
from raiden.transfer import channel
from raiden.transfer.architecture import (
    Event,
    StateChange,
    TransitionResult,
)
from raiden.transfer.events import EventTransferSentFailed
from raiden.transfer.mediated_transfer.events import EventUnlockFailed
from raiden.transfer.mediated_transfer import initiator, mediator
from raiden.transfer.mediated_transfer.state_change import (
    ActionCancelRoute,
    ActionInitInitiator,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state_change import ActionCancelPayment

# TODO:
# - Add synchronization for expired locks (issue #193).
#   Transfers added to the canceled list by an ActionCancelRoute are stale in
#   the channels merkle tree, while this doesn't increase the messages sizes
#   nor does it interfere with the guarantees of finality it increases memory
#   usage for each end, since the full merkle tree must be saved to compute
#   it's root.


def iteration_from_sub(
        payment_state: InitiatorPaymentState,
        iteration: TransitionResult,
) -> TransitionResult:

    if iteration.new_state:
        payment_state.initiator = iteration.new_state
        return TransitionResult(payment_state, iteration.events)
    return iteration


def can_cancel(payment_state: InitiatorPaymentState) -> bool:
    """ A transfer is only cancellable until the secret is revealed. """
    return (
        payment_state.initiator is None or
        payment_state.initiator.revealsecret is None
    )


def sanity_check(payment_state: InitiatorPaymentState):
    assert (
        payment_state is None or payment_state.initiator is not None
    ), 'either the task must be finished or there must be an initiator transfer pending'


def events_for_cancel_current_route(transfer_description) -> typing.List[Event]:
    unlock_failed = EventUnlockFailed(
        identifier=transfer_description.payment_identifier,
        secrethash=transfer_description.secrethash,
        reason='route was canceled',
    )
    return [unlock_failed]


def cancel_current_route(payment_state: InitiatorPaymentState) -> typing.List[Event]:
    """ Cancel current route.

    This allows a new route to be tried.
    """
    assert can_cancel(payment_state), 'Cannot cancel a route after the secret is revealed'

    transfer_description = payment_state.initiator.transfer_description

    payment_state.cancelled_channels.append(payment_state.initiator.channel_identifier)
    payment_state.initiator = None

    return events_for_cancel_current_route(transfer_description)


def handle_init(
        payment_state: InitiatorPaymentState,
        state_change: ActionInitInitiator,
        channelidentifiers_to_channels: initiator.ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    if payment_state is None:
        sub_iteration = initiator.try_new_route(
            channelidentifiers_to_channels,
            state_change.routes,
            state_change.transfer,
            pseudo_random_generator,
            block_number,
        )

        events = sub_iteration.events
        if sub_iteration.new_state:
            payment_state = InitiatorPaymentState(sub_iteration.new_state)
    else:
        events = list()

    iteration = TransitionResult(payment_state, events)
    return iteration


def handle_cancelroute(
        payment_state: InitiatorPaymentState,
        state_change: ActionCancelRoute,
        channelidentifiers_to_channels: initiator.ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    events = list()
    if can_cancel(payment_state):
        transfer_description = payment_state.initiator.transfer_description
        cancel_events = cancel_current_route(payment_state)

        msg = 'The previous transfer must be cancelled prior to trying a new route'
        assert payment_state.initiator is None, msg
        sub_iteration = initiator.try_new_route(
            channelidentifiers_to_channels,
            state_change.routes,
            transfer_description,
            pseudo_random_generator,
            block_number,
        )

        events.extend(cancel_events)
        events.extend(sub_iteration.events)

        if sub_iteration.new_state:
            payment_state.initiator = sub_iteration.new_state
        else:
            payment_state = None

    iteration = TransitionResult(payment_state, events)

    return iteration


def handle_cancelpayment(payment_state: InitiatorPaymentState) -> TransitionResult:
    """ Cancel the payment. """
    assert can_cancel(payment_state), 'Cannot cancel a transfer after the secret is revealed'

    transfer_description = payment_state.initiator.transfer_description
    cancel_events = cancel_current_route(payment_state)

    cancel = EventTransferSentFailed(
        identifier=transfer_description.payment_identifier,
        reason='user canceled transfer',
    )
    cancel_events.append(cancel)

    return TransitionResult(None, cancel_events)


def handle_transferrefundcancelroute(
        payment_state: InitiatorPaymentState,
        state_change: ReceiveTransferRefundCancelRoute,
        channelidentifiers_to_channels: initiator.ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: typing.BlockNumber,
) -> TransitionResult:

    channel_identifier = payment_state.initiator.channel_identifier
    channel_state = channelidentifiers_to_channels[channel_identifier]
    refund_transfer = state_change.transfer
    original_transfer = payment_state.initiator.transfer

    if channel_state.close_transaction:
        closed_block_number = channel_state.close_transaction.finished_block_number
    else:
        closed_block_number = None

    # This is overcommiting, since the initiator knows the secret it doesn't
    # need to wait for reveal_timeout blocks.
    timeout_blocks = mediator.get_timeout_blocks(
        channel_state.settle_timeout,
        closed_block_number,
        original_transfer.lock.expiration,
        block_number,
    )
    lock_timeout = timeout_blocks - channel_state.reveal_timeout
    maximum_expiration = lock_timeout + block_number

    is_valid_lock = (
        refund_transfer.lock.secrethash == original_transfer.lock.secrethash and
        refund_transfer.lock.amount == original_transfer.lock.amount and
        refund_transfer.lock.expiration <= maximum_expiration
    )

    is_valid_refund = channel.refund_transfer_matches_received(
        refund_transfer,
        original_transfer,
    )

    events = list()
    if is_valid_lock and is_valid_refund:
        is_valid, channel_events, _ = channel.handle_receive_refundtransfercancelroute(
            channel_state,
            refund_transfer,
        )

        events.extend(channel_events)

        if is_valid:
            old_description = payment_state.initiator.transfer_description
            transfer_description = TransferDescriptionWithSecretState(
                old_description.payment_identifier,
                old_description.amount,
                old_description.token_network_identifier,
                old_description.initiator,
                old_description.target,
                state_change.secret,
            )
            payment_state.initiator.transfer_description = transfer_description

            sub_iteration = handle_cancelroute(
                payment_state,
                state_change,
                channelidentifiers_to_channels,
                pseudo_random_generator,
                block_number,
            )

            events.extend(sub_iteration.events)
            if sub_iteration.new_state is None:
                payment_state = None

    iteration = TransitionResult(payment_state, events)

    return iteration


def handle_secretreveal(
        payment_state: InitiatorPaymentState,
        state_change: ReceiveSecretReveal,
        channelidentifiers_to_channels: initiator.ChannelMap,
        pseudo_random_generator: random.Random,
) -> TransitionResult:
    channel_identifier = payment_state.initiator.channel_identifier
    channel_state = channelidentifiers_to_channels[channel_identifier]
    sub_iteration = initiator.handle_secretreveal(
        payment_state.initiator,
        state_change,
        channel_state,
        pseudo_random_generator,
    )
    iteration = iteration_from_sub(payment_state, sub_iteration)
    return iteration


def state_transition(
        payment_state: InitiatorPaymentState,
        state_change: StateChange,
        channelidentifiers_to_channels: initiator.ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    # pylint: disable=unidiomatic-typecheck
    if type(state_change) == ActionInitInitiator:
        iteration = handle_init(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ReceiveSecretRequest:
        sub_iteration = initiator.handle_secretrequest(
            payment_state.initiator,
            state_change,
            pseudo_random_generator,
        )
        iteration = iteration_from_sub(payment_state, sub_iteration)
    elif type(state_change) == ActionCancelRoute:
        iteration = handle_cancelroute(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ReceiveTransferRefundCancelRoute:
        iteration = handle_transferrefundcancelroute(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ActionCancelPayment:
        iteration = handle_cancelpayment(
            payment_state,
        )
    elif type(state_change) == ReceiveSecretReveal:
        iteration = handle_secretreveal(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
        )
    else:
        iteration = TransitionResult(payment_state, list())

    sanity_check(iteration.new_state)

    return iteration
