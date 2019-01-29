import random

from raiden.transfer import channel
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.mediated_transfer import initiator
from raiden.transfer.mediated_transfer.events import EventUnlockClaimFailed, EventUnlockFailed
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionCancelRoute,
    ActionInitInitiator,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.state import NettingChannelState
from raiden.transfer.state_change import ActionCancelPayment, Block, ContractReceiveSecretReveal
from raiden.utils.typing import BlockNumber, ChannelMap, List

# TODO:
# - Add synchronization for expired locks (issue #193).
#   Transfers added to the canceled list by an ActionCancelRoute are stale in
#   the channels merkle tree, while this doesn't increase the messages sizes
#   nor does it interfere with the guarantees of finality it increases memory
#   usage for each end, since the full merkle tree must be saved to compute
#   it's root.


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


def events_for_cancel_current_route(transfer_description) -> List[Event]:
    unlock_failed = EventUnlockFailed(
        identifier=transfer_description.payment_identifier,
        secrethash=transfer_description.secrethash,
        reason='route was canceled',
    )
    return [unlock_failed]


def cancel_current_route(payment_state: InitiatorPaymentState) -> List[Event]:
    """ Cancel current route.

    This allows a new route to be tried.
    """
    assert can_cancel(payment_state), 'Cannot cancel a route after the secret is revealed'

    transfer_description = payment_state.initiator.transfer_description

    payment_state.cancelled_channels.append(payment_state.initiator.channel_identifier)
    payment_state.initiator = None

    return events_for_cancel_current_route(transfer_description)


def subdispatch_to_initiatortransfer(
        payment_state: InitiatorPaymentState,
        state_change: StateChange,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    events = list()
    for initiator_state in payment_state.initiator_transfers:
        channel_identifier = initiator_state.channel_identifier
        channel_state = channelidentifiers_to_channels[channel_identifier]
        if not channel_state:
            continue

        sub_iteration = initiator.state_transition(
            initiator_state=initiator_state,
            state_change=state_change,
            channel_state=channel_state,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
        events.extend(sub_iteration.events)
    return TransitionResult(payment_state, events)


def handle_block(
        payment_state: InitiatorPaymentState,
        state_change: Block,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    return subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )


def handle_init(
        payment_state: InitiatorPaymentState,
        state_change: ActionInitInitiator,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    events: List[Event]
    if payment_state is None:
        sub_iteration = initiator.try_new_route(
            old_initiator_state=None,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            available_routes=state_change.routes,
            transfer_description=state_change.transfer,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )

        events = sub_iteration.events
        if sub_iteration.new_state:
            payment_state = InitiatorPaymentState([sub_iteration.new_state])
    else:
        events = list()

    iteration = TransitionResult(payment_state, events)
    return iteration


def handle_cancelroute(
        payment_state: InitiatorPaymentState,
        state_change: ActionCancelRoute,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    events: List[Event] = list()
    if can_cancel(payment_state):
        old_initiator_state = payment_state.initiator
        transfer_description = payment_state.initiator.transfer_description
        cancel_events = cancel_current_route(payment_state)

        msg = 'The previous transfer must be cancelled prior to trying a new route'
        assert payment_state.initiator is None, msg

        sub_iteration = initiator.try_new_route(
            old_initiator_state=old_initiator_state,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            available_routes=state_change.routes,
            transfer_description=transfer_description,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )

        events.extend(cancel_events)
        events.extend(sub_iteration.events)
        assert sub_iteration.new_state
        payment_state.initiator = sub_iteration.new_state

    iteration = TransitionResult(payment_state, events)

    return iteration


def handle_cancelpayment(
        payment_state: InitiatorPaymentState,
        channel_state: NettingChannelState,
) -> TransitionResult:
    """ Cancel the payment and all related transfers. """
    # Cannot cancel a transfer after the secret is revealed
    if can_cancel(payment_state):
        transfer_description = payment_state.initiator.transfer_description
        cancel_events = cancel_current_route(payment_state)

        cancel = EventPaymentSentFailed(
            payment_network_identifier=channel_state.payment_network_identifier,
            token_network_identifier=channel_state.token_network_identifier,
            identifier=transfer_description.payment_identifier,
            target=transfer_description.target,
            reason='user canceled payment',
        )
        cancel_events.append(cancel)

        iteration = TransitionResult(None, cancel_events)
    else:
        iteration = TransitionResult(payment_state, list())

    return iteration


def handle_transferrefundcancelroute(
        payment_state: InitiatorPaymentState,
        state_change: ReceiveTransferRefundCancelRoute,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:

    channel_identifier = payment_state.initiator.channel_identifier
    channel_state = channelidentifiers_to_channels[channel_identifier]
    refund_transfer = state_change.transfer
    original_transfer = payment_state.initiator.transfer

    is_valid_lock = (
        refund_transfer.lock.secrethash == original_transfer.lock.secrethash and
        refund_transfer.lock.amount == original_transfer.lock.amount and
        refund_transfer.lock.expiration == original_transfer.lock.expiration
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
                old_description.payment_network_identifier,
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


def handle_lock_expired(
        payment_state: InitiatorPaymentState,
        state_change: ReceiveLockExpired,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    """Initiator also needs to handle LockExpired messages when refund transfers are involved.

    A -> B -> C

    - A sends locked transfer to B
    - B attempted to forward to C but has not enough capacity
    - B sends a refund transfer with the same secrethash back to A
    - When the lock expires B will also send a LockExpired message to A
    - A needs to be able to properly process it

    Related issue: https://github.com/raiden-network/raiden/issues/3183
"""
    channel_identifier = payment_state.initiator.channel_identifier
    channel_state = channelidentifiers_to_channels[channel_identifier]
    secrethash = payment_state.initiator.transfer.lock.secrethash
    result = channel.handle_receive_lock_expired(
        channel_state=channel_state,
        state_change=state_change,
        block_number=block_number,
    )

    if not channel.get_lock(result.new_state.partner_state, secrethash):
        transfer = payment_state.initiator.transfer
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason='Lock expired',
        )
        result.events.append(unlock_failed)

    return TransitionResult(payment_state, result.events)


def handle_offchain_secretreveal(
        payment_state: InitiatorPaymentState,
        state_change: ReceiveSecretReveal,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    return subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )


def handle_onchain_secretreveal(
        payment_state: InitiatorPaymentState,
        state_change: ReceiveSecretReveal,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    return subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )


def handle_secretrequest(
        payment_state: InitiatorPaymentState,
        state_change: ReceiveSecretRequest,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    return subdispatch_to_initiatortransfer(
        payment_state,
        state_change,
        channelidentifiers_to_channels,
        pseudo_random_generator,
        block_number=block_number,
    )


def state_transition(
        payment_state: InitiatorPaymentState,
        state_change: StateChange,
        channelidentifiers_to_channels: ChannelMap,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult:
    # pylint: disable=unidiomatic-typecheck
    if type(state_change) == Block:
        iteration = handle_block(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ActionInitInitiator:
        iteration = handle_init(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ReceiveSecretRequest:
        iteration = handle_secretrequest(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
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
        channel_identifier = payment_state.initiator.channel_identifier
        channel_state = channelidentifiers_to_channels[channel_identifier]
        iteration = handle_cancelpayment(
            payment_state,
            channel_state,
        )
    elif type(state_change) == ReceiveSecretReveal:
        iteration = handle_offchain_secretreveal(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ReceiveLockExpired:
        iteration = handle_lock_expired(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        iteration = handle_onchain_secretreveal(
            payment_state,
            state_change,
            channelidentifiers_to_channels,
            pseudo_random_generator,
            block_number,
        )
    else:
        iteration = TransitionResult(payment_state, list())

    sanity_check(iteration.new_state)

    return iteration
