import random
from typing import Tuple

from raiden.transfer import channel, routes
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.mediated_transfer import initiator
from raiden.transfer.mediated_transfer.events import (
    EventRouteFailed,
    EventUnlockClaimFailed,
    EventUnlockFailed,
)
from raiden.transfer.mediated_transfer.state import (
    InitiatorPaymentState,
    InitiatorTransferState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionTransferReroute,
    ReceiveLockExpired,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    ReceiveTransferCancelRoute,
)
from raiden.transfer.state import NettingChannelState, RouteState, get_address_metadata
from raiden.transfer.state_change import ActionCancelPayment, Block, ContractReceiveSecretReveal
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    BlockNumber,
    ChannelID,
    Dict,
    List,
    Optional,
    SecretHash,
    TokenNetworkAddress,
    cast,
)


def clear_if_finalized(
    iteration: TransitionResult,
) -> TransitionResult[Optional[InitiatorPaymentState]]:
    """Clear the initiator payment task if all transfers have been finalized
    or expired."""
    state = cast(InitiatorPaymentState, iteration.new_state)

    if state is None:
        return iteration  # type: ignore

    if len(state.initiator_transfers) == 0:
        return TransitionResult(None, iteration.events)

    return iteration


def transfer_exists(payment_state: InitiatorPaymentState, secrethash: SecretHash) -> bool:
    return secrethash in payment_state.initiator_transfers


def cancel_other_transfers(payment_state: InitiatorPaymentState) -> None:
    for initiator_state in payment_state.initiator_transfers.values():
        initiator_state.transfer_state = "transfer_cancelled"


def can_cancel(initiator: InitiatorTransferState) -> bool:
    """A transfer is only cancellable until the secret is revealed."""
    return initiator.transfer_state != "transfer_secret_revealed"


def events_for_cancel_current_route(
    route_state: RouteState, transfer_description: TransferDescriptionWithSecretState
) -> List[Event]:
    return [
        EventUnlockFailed(
            identifier=transfer_description.payment_identifier,
            secrethash=transfer_description.secrethash,
            reason="route was canceled",
        ),
        EventRouteFailed(
            secrethash=transfer_description.secrethash,
            route=route_state.route,
            token_network_address=transfer_description.token_network_address,
        ),
    ]


def cancel_current_route(
    payment_state: InitiatorPaymentState, initiator_state: InitiatorTransferState
) -> List[Event]:
    """Cancel current route.

    This allows a new route to be tried.
    """

    assert can_cancel(initiator_state), "Cannot cancel a route after the secret is revealed"

    payment_state.cancelled_channels.append(initiator_state.channel_identifier)

    return events_for_cancel_current_route(
        route_state=initiator_state.route,
        transfer_description=initiator_state.transfer_description,
    )


def subdispatch_to_initiatortransfer(
    payment_state: InitiatorPaymentState,
    initiator_state: InitiatorTransferState,
    state_change: StateChange,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorTransferState]]:
    channel_identifier = initiator_state.channel_identifier
    channel_state = channelidentifiers_to_channels.get(channel_identifier)
    if not channel_state:
        return TransitionResult(initiator_state, list())

    sub_iteration = initiator.state_transition(
        initiator_state=initiator_state,
        state_change=state_change,
        channel_state=channel_state,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    if sub_iteration.new_state is None:
        del payment_state.initiator_transfers[initiator_state.transfer.lock.secrethash]

    return sub_iteration


def subdispatch_to_all_initiatortransfer(
    payment_state: InitiatorPaymentState,
    state_change: StateChange,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    events: List[Event] = list()
    """ Copy and iterate over the list of keys because this loop
    will alter the `initiator_transfers` list and this is not
    allowed if iterating over the original list.
    """
    for secrethash in list(payment_state.initiator_transfers.keys()):
        initiator_state = payment_state.initiator_transfers[secrethash]
        sub_iteration = subdispatch_to_initiatortransfer(
            payment_state=payment_state,
            initiator_state=initiator_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
        events.extend(sub_iteration.events)
    return TransitionResult(payment_state, events)


def handle_block(
    payment_state: InitiatorPaymentState,
    state_change: Block,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    return subdispatch_to_all_initiatortransfer(
        payment_state=payment_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )


def handle_init(
    payment_state: Optional[InitiatorPaymentState],
    state_change: ActionInitInitiator,
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorPaymentState]]:
    events: List[Event] = list()
    if payment_state is None:
        sub_iteration = initiator.try_new_route(
            addresses_to_channel=addresses_to_channel,
            candidate_route_states=state_change.routes,
            transfer_description=state_change.transfer,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )

        events = sub_iteration.events
        if sub_iteration.new_state:
            payment_state = InitiatorPaymentState(
                initiator_transfers={
                    sub_iteration.new_state.transfer.lock.secrethash: sub_iteration.new_state
                },
                routes=state_change.routes,
            )

    return TransitionResult(payment_state, events)


def handle_cancelpayment(
    payment_state: InitiatorPaymentState,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
) -> TransitionResult[InitiatorPaymentState]:
    """Cancel the payment and all related transfers."""
    # Cannot cancel a transfer after the secret is revealed
    events = list()
    for initiator_state in payment_state.initiator_transfers.values():
        channel_identifier = initiator_state.channel_identifier
        channel_state = channelidentifiers_to_channels.get(channel_identifier)

        if not channel_state or not initiator_state:
            continue

        if can_cancel(initiator_state):
            transfer_description = initiator_state.transfer_description
            cancel_events = cancel_current_route(payment_state, initiator_state)

            initiator_state.transfer_state = "transfer_cancelled"

            cancel = EventPaymentSentFailed(
                token_network_registry_address=channel_state.token_network_registry_address,
                token_network_address=channel_state.token_network_address,
                identifier=transfer_description.payment_identifier,
                target=transfer_description.target,
                reason="user canceled payment",
            )
            cancel_events.append(cancel)

            events.extend(cancel_events)

    return TransitionResult(payment_state, events)


def handle_failroute(
    payment_state: InitiatorPaymentState, state_change: ReceiveTransferCancelRoute
) -> TransitionResult[InitiatorPaymentState]:

    events: List[Event] = list()

    initiator_state = payment_state.initiator_transfers.get(state_change.transfer.lock.secrethash)
    if initiator_state is not None and can_cancel(initiator_state):
        cancel_events = cancel_current_route(payment_state, initiator_state)
        events.extend(cancel_events)

    return TransitionResult(payment_state, events)


def handle_transferreroute(
    payment_state: InitiatorPaymentState,
    state_change: ActionTransferReroute,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:

    try:
        initiator_state = payment_state.initiator_transfers[state_change.transfer.lock.secrethash]
        channel_identifier = initiator_state.channel_identifier
        channel_state = channelidentifiers_to_channels[channel_identifier]
    except KeyError:
        return TransitionResult(payment_state, list())

    refund_transfer = state_change.transfer
    original_transfer = initiator_state.transfer

    is_valid_lock = (
        refund_transfer.lock.secrethash == original_transfer.lock.secrethash
        and refund_transfer.lock.amount == original_transfer.lock.amount
        and refund_transfer.lock.expiration == original_transfer.lock.expiration
    )

    is_valid_refund = channel.refund_transfer_matches_transfer(refund_transfer, original_transfer)

    recipient_address = channel_state.partner_state.address
    recipient_metadata = get_address_metadata(recipient_address, payment_state.routes)
    is_valid, channel_events, _ = channel.handle_receive_lockedtransfer(
        channel_state, refund_transfer, recipient_metadata=recipient_metadata
    )

    if not is_valid_lock or not is_valid_refund or not is_valid:
        return TransitionResult(payment_state, list())

    events: List[Event] = []
    events.extend(channel_events)

    old_description = initiator_state.transfer_description
    filtered_route_states = routes.filter_acceptable_routes(
        route_states=payment_state.routes,
        blacklisted_channel_ids=payment_state.cancelled_channels,
        addresses_to_channel=addresses_to_channel,
        token_network_address=old_description.token_network_address,
    )
    transfer_description = TransferDescriptionWithSecretState(
        token_network_registry_address=old_description.token_network_registry_address,
        payment_identifier=old_description.payment_identifier,
        amount=old_description.amount,
        token_network_address=old_description.token_network_address,
        initiator=old_description.initiator,
        target=old_description.target,
        secret=state_change.secret,
        secrethash=state_change.secrethash,
    )

    sub_iteration = initiator.try_new_route(
        addresses_to_channel=addresses_to_channel,
        candidate_route_states=filtered_route_states,
        transfer_description=transfer_description,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    events.extend(sub_iteration.events)

    if sub_iteration.new_state is None:
        # Here we don't delete the initiator state, but instead let it live.
        # It will be deleted when the lock expires. We do that so that we
        # still have an initiator payment task around to process the
        # LockExpired message that our partner will send us.
        # https://github.com/raiden-network/raiden/issues/3146#issuecomment-447378046
        return TransitionResult(payment_state, events)

    new_transfer = sub_iteration.new_state.transfer
    payment_state.initiator_transfers[new_transfer.lock.secrethash] = sub_iteration.new_state

    return TransitionResult(payment_state, events)


def handle_lock_expired(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveLockExpired,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    """Initiator also needs to handle LockExpired messages when refund transfers are involved.

    A -> B -> C

    - A sends locked transfer to B
    - B attempted to forward to C but has not enough capacity
    - B sends a refund transfer with the same secrethash back to A
    - When the lock expires B will also send a LockExpired message to A
    - A needs to be able to properly process it

    Related issue: https://github.com/raiden-network/raiden/issues/3183"""
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)
    if not initiator_state:
        return TransitionResult(payment_state, list())

    channel_identifier = initiator_state.channel_identifier
    channel_state = channelidentifiers_to_channels.get(channel_identifier)

    if not channel_state:
        return TransitionResult(payment_state, list())

    secrethash = initiator_state.transfer.lock.secrethash
    recipient_address = channel_state.partner_state.address
    recipient_metadata = get_address_metadata(recipient_address, payment_state.routes)
    result = channel.handle_receive_lock_expired(
        channel_state=channel_state,
        state_change=state_change,
        block_number=block_number,
        recipient_metadata=recipient_metadata,
    )
    assert result.new_state, "handle_receive_lock_expired should not delete the task"

    if not channel.get_lock(result.new_state.partner_state, secrethash):
        transfer = initiator_state.transfer
        unlock_failed = EventUnlockClaimFailed(
            identifier=transfer.payment_identifier,
            secrethash=transfer.lock.secrethash,
            reason="Lock expired",
        )
        result.events.append(unlock_failed)

    return TransitionResult(payment_state, result.events)


def handle_offchain_secretreveal(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveSecretReveal,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    assert (
        initiator_state.transfer_state != "transfer_cancelled"
    ), "Can't handle reveal for cancelled transfer"

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    # The current secretreveal unlocked the transfer
    if not transfer_exists(payment_state, state_change.secrethash):
        cancel_other_transfers(payment_state)

    return TransitionResult(payment_state, sub_iteration.events)


def handle_onchain_secretreveal(
    payment_state: InitiatorPaymentState,
    state_change: ContractReceiveSecretReveal,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    assert (
        initiator_state.transfer_state != "transfer_cancelled"
    ), "Must not reveal secret for cancelled payment"

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    # The current secretreveal unlocked the transfer
    if not transfer_exists(payment_state, state_change.secrethash):
        cancel_other_transfers(payment_state)

    return TransitionResult(payment_state, sub_iteration.events)


def handle_secretrequest(
    payment_state: InitiatorPaymentState,
    state_change: ReceiveSecretRequest,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[InitiatorPaymentState]:
    initiator_state = payment_state.initiator_transfers.get(state_change.secrethash)

    if not initiator_state:
        return TransitionResult(payment_state, list())

    if initiator_state.transfer_state == "transfer_cancelled":
        return TransitionResult(payment_state, list())

    sub_iteration = subdispatch_to_initiatortransfer(
        payment_state=payment_state,
        initiator_state=initiator_state,
        state_change=state_change,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    return TransitionResult(payment_state, sub_iteration.events)


def state_transition(
    payment_state: Optional[InitiatorPaymentState],
    state_change: StateChange,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorPaymentState]]:
    # pylint: disable=unidiomatic-typecheck
    iteration: TransitionResult[Optional[InitiatorPaymentState]]

    if type(state_change) == Block:
        assert isinstance(state_change, Block), MYPY_ANNOTATION
        assert payment_state, "Block state changes should be accompanied by a valid payment state"
        iteration = handle_block(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ActionInitInitiator:
        assert isinstance(state_change, ActionInitInitiator), MYPY_ANNOTATION
        iteration = handle_init(
            payment_state=payment_state,
            state_change=state_change,
            addresses_to_channel=addresses_to_channel,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ReceiveTransferCancelRoute:
        assert isinstance(state_change, ReceiveTransferCancelRoute), MYPY_ANNOTATION
        assert (
            payment_state
        ), "ReceiveTransferCancelRoute should be accompanied by a valid payment state"
        iteration = handle_failroute(payment_state=payment_state, state_change=state_change)
    elif type(state_change) == ActionTransferReroute:
        assert isinstance(state_change, ActionTransferReroute), MYPY_ANNOTATION
        msg = "ActionTransferReroute should be accompanied by a valid payment state"
        assert payment_state, msg
        iteration = handle_transferreroute(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            addresses_to_channel=addresses_to_channel,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ReceiveSecretRequest:
        assert isinstance(state_change, ReceiveSecretRequest), MYPY_ANNOTATION
        assert payment_state, "ReceiveSecretRequest should be accompanied by a valid payment state"
        iteration = handle_secretrequest(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ActionCancelPayment:
        assert isinstance(state_change, ActionCancelPayment), MYPY_ANNOTATION
        assert payment_state, "ActionCancelPayment should be accompanied by a valid payment state"
        iteration = handle_cancelpayment(
            payment_state=payment_state,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
        )
    elif type(state_change) == ReceiveSecretReveal:
        assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
        assert payment_state, "ReceiveSecretReveal should be accompanied by a valid payment state"
        iteration = handle_offchain_secretreveal(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ReceiveLockExpired:
        assert isinstance(state_change, ReceiveLockExpired), MYPY_ANNOTATION
        assert payment_state, "ReceiveLockExpired should be accompanied by a valid payment state"
        iteration = handle_lock_expired(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            block_number=block_number,
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
        msg = "ContractReceiveSecretReveal should be accompanied by a valid payment state"
        assert payment_state, msg
        iteration = handle_onchain_secretreveal(
            payment_state=payment_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    else:
        iteration = TransitionResult(payment_state, list())

    return clear_if_finalized(iteration)
