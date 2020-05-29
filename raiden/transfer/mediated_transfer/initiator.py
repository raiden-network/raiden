import random
from math import ceil

from raiden.constants import ABSENT_SECRET
from raiden.settings import (
    DEFAULT_MEDIATION_FEE_MARGIN,
    DEFAULT_WAIT_BEFORE_LOCK_REMOVAL,
    MAX_MEDIATION_FEE_PERC,
    PAYMENT_AMOUNT_BASED_FEE_MARGIN,
)
from raiden.transfer import channel, routes
from raiden.transfer.architecture import Event, TransitionResult
from raiden.transfer.events import (
    EventInvalidSecretRequest,
    EventPaymentSentFailed,
    EventPaymentSentSuccess,
)
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE
from raiden.transfer.mediated_transfer.events import (
    EventRouteFailed,
    EventUnlockFailed,
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
    ChannelState,
    NettingChannelState,
    RouteState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal, StateChange
from raiden.transfer.utils import is_valid_secret_reveal
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    BlockExpiration,
    BlockNumber,
    ChannelID,
    Dict,
    FeeAmount,
    List,
    MessageID,
    NodeNetworkStateMap,
    Optional,
    PaymentAmount,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
)


def calculate_fee_margin(payment_amount: PaymentAmount, estimated_fee: FeeAmount) -> FeeAmount:
    if estimated_fee == 0:
        # If the total fees are zero, we assume that no fees are set. If the
        # fees sum up to zero incidentally, we should add a margin, but we
        # can't detect that case.
        return FeeAmount(0)

    return FeeAmount(
        int(
            ceil(
                abs(estimated_fee) * DEFAULT_MEDIATION_FEE_MARGIN
                + payment_amount * PAYMENT_AMOUNT_BASED_FEE_MARGIN
            )
        )
    )


def calculate_safe_amount_with_fee(
    payment_amount: PaymentAmount, estimated_fee: FeeAmount
) -> PaymentWithFeeAmount:
    """ Calculates the total payment amount

    This total amount consists of the payment amount, the estimated fees as well as a
    small margin that is added to increase the likelihood of payments succeeding in
    conditions where channels are used for multiple payments.

    We could get much better margins by considering that we only need margins
    for imbalance fees. See
    https://github.com/raiden-network/raiden-services/issues/569.
    """
    return PaymentWithFeeAmount(
        payment_amount + estimated_fee + calculate_fee_margin(payment_amount, estimated_fee)
    )


def events_for_unlock_lock(
    initiator_state: InitiatorTransferState,
    channel_state: NettingChannelState,
    secret: Secret,
    secrethash: SecretHash,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> List[Event]:
    """ Unlocks the lock offchain, and emits the events for the successful payment. """
    # next hop learned the secret, unlock the token locally and send the
    # lock claim message to next hop
    transfer_description = initiator_state.transfer_description

    message_identifier = message_identifier_from_prng(pseudo_random_generator)
    unlock_lock = channel.send_unlock(
        channel_state=channel_state,
        message_identifier=message_identifier,
        payment_identifier=transfer_description.payment_identifier,
        secret=secret,
        secrethash=secrethash,
        block_number=block_number,
    )

    payment_sent_success = EventPaymentSentSuccess(
        token_network_registry_address=channel_state.token_network_registry_address,
        token_network_address=channel_state.token_network_address,
        identifier=transfer_description.payment_identifier,
        amount=transfer_description.amount,
        target=transfer_description.target,
        secret=secret,
        route=initiator_state.route.route,
    )

    unlock_success = EventUnlockSuccess(
        transfer_description.payment_identifier, transfer_description.secrethash
    )

    return [unlock_lock, payment_sent_success, unlock_success]


def handle_block(
    initiator_state: InitiatorTransferState,
    state_change: Block,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
) -> TransitionResult[Optional[InitiatorTransferState]]:
    """ Checks if the lock has expired, and if it has sends a remove expired
    lock and emits the failing events.
    """
    secrethash = initiator_state.transfer.lock.secrethash
    locked_lock = channel_state.our_state.secrethashes_to_lockedlocks.get(secrethash)

    if not locked_lock:
        if channel_state.partner_state.secrethashes_to_lockedlocks.get(secrethash):
            return TransitionResult(initiator_state, list())
        else:
            # if lock is not in our or our partner's locked locks then the
            # task can go
            return TransitionResult(None, list())

    lock_expiration_threshold = BlockExpiration(
        locked_lock.expiration + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL
    )
    lock_has_expired = channel.is_lock_expired(
        end_state=channel_state.our_state,
        lock=locked_lock,
        block_number=state_change.block_number,
        lock_expiration_threshold=lock_expiration_threshold,
    )

    events: List[Event] = list()

    if lock_has_expired and initiator_state.transfer_state != "transfer_expired":
        is_channel_open = channel.get_status(channel_state) == ChannelState.STATE_OPENED
        if is_channel_open:
            expired_lock_events = channel.send_lock_expired(
                channel_state=channel_state,
                locked_lock=locked_lock,
                pseudo_random_generator=pseudo_random_generator,
            )
            events.extend(expired_lock_events)

        if initiator_state.received_secret_request:
            reason = "bad secret request message from target"
        else:
            reason = "lock expired"

        transfer_description = initiator_state.transfer_description
        payment_identifier = transfer_description.payment_identifier
        # TODO: When we introduce multiple transfers per payment this needs to be
        #       reconsidered. As we would want to try other routes once a route
        #       has failed, and a transfer failing does not mean the entire payment
        #       would have to fail.
        #       Related issue: https://github.com/raiden-network/raiden/issues/2329
        payment_failed = EventPaymentSentFailed(
            token_network_registry_address=transfer_description.token_network_registry_address,
            token_network_address=transfer_description.token_network_address,
            identifier=payment_identifier,
            target=transfer_description.target,
            reason=reason,
        )
        route_failed = EventRouteFailed(
            secrethash=secrethash,
            route=initiator_state.route.route,
            token_network_address=transfer_description.token_network_address,
        )
        unlock_failed = EventUnlockFailed(
            identifier=payment_identifier,
            secrethash=initiator_state.transfer_description.secrethash,
            reason=reason,
        )

        lock_exists = channel.lock_exists_in_either_channel_side(
            channel_state=channel_state, secrethash=secrethash
        )
        initiator_state.transfer_state = "transfer_expired"

        return TransitionResult(
            # If the lock is either in our state or partner state we keep the
            # task around to wait for the LockExpired messages to sync.
            # Check https://github.com/raiden-network/raiden/issues/3183
            initiator_state if lock_exists else None,
            events + [payment_failed, route_failed, unlock_failed],
        )
    else:
        return TransitionResult(initiator_state, events)


def try_new_route(
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    nodeaddresses_to_networkstates: NodeNetworkStateMap,
    candidate_route_states: List[RouteState],
    transfer_description: TransferDescriptionWithSecretState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorTransferState]]:

    initiator_state = None
    events: List[Event] = list()
    route_fee_exceeds_max = False

    channel_state = None
    route_state = None

    reachable_route_states = routes.filter_reachable_routes(
        candidate_route_states, nodeaddresses_to_networkstates
    )

    for reachable_route_state in reachable_route_states:
        candidate_channel_state = channelidentifiers_to_channels[
            reachable_route_state.forward_channel_id
        ]

        amount_with_fee = calculate_safe_amount_with_fee(
            payment_amount=transfer_description.amount,
            estimated_fee=reachable_route_state.estimated_fee,
        )
        # https://github.com/raiden-network/raiden/issues/4751
        # If the transfer amount + fees exceeds a percentage of the
        # initial amount then don't use this route
        max_amount_limit = transfer_description.amount + int(
            transfer_description.amount * MAX_MEDIATION_FEE_PERC
        )
        if amount_with_fee > max_amount_limit:
            route_fee_exceeds_max = True
            continue

        channel_usability_state = channel.is_channel_usable_for_new_transfer(
            channel_state=candidate_channel_state,
            transfer_amount=amount_with_fee,
            lock_timeout=transfer_description.lock_timeout,
        )
        if channel_usability_state is channel.ChannelUsability.USABLE:
            channel_state = candidate_channel_state
            route_state = reachable_route_state
            break

    if route_state is None:
        if not reachable_route_states:
            reason = "there is no route available"
        else:
            reason = "none of the available routes could be used"

        if route_fee_exceeds_max:
            reason += (
                " and at least one of them exceeded the maximum fee limit "
                "(see https://docs.raiden.network/using-raiden/mediation-fees#frequently-asked-questions)"  # noqa
            )

        transfer_failed = EventPaymentSentFailed(
            token_network_registry_address=transfer_description.token_network_registry_address,
            token_network_address=transfer_description.token_network_address,
            identifier=transfer_description.payment_identifier,
            target=transfer_description.target,
            reason=reason,
        )
        events.append(transfer_failed)

        initiator_state = None

    else:
        assert channel_state is not None, "We must have a channel_state if we have a route_state"

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        lockedtransfer_event = send_lockedtransfer(
            transfer_description=transfer_description,
            channel_state=channel_state,
            message_identifier=message_identifier,
            block_number=block_number,
            route_state=route_state,
            route_states=reachable_route_states,
        )

        initiator_state = InitiatorTransferState(
            route=route_state,
            transfer_description=transfer_description,
            channel_identifier=channel_state.identifier,
            transfer=lockedtransfer_event.transfer,
        )
        events.append(lockedtransfer_event)

    return TransitionResult(initiator_state, events)


def send_lockedtransfer(
    transfer_description: TransferDescriptionWithSecretState,
    channel_state: NettingChannelState,
    message_identifier: MessageID,
    block_number: BlockNumber,
    route_state: RouteState,
    route_states: List[RouteState],
) -> SendLockedTransfer:
    """ Create a mediated transfer using channel. """
    assert (
        channel_state.token_network_address == transfer_description.token_network_address
    ), "token_network_address mismatch"

    lock_expiration = channel.get_safe_initial_expiration(
        block_number, channel_state.reveal_timeout, transfer_description.lock_timeout
    )

    # The payment amount and the fee amount must be included in the locked
    # amount, as a guarantee to the mediator that the fee will be claimable
    # on-chain.
    total_amount = calculate_safe_amount_with_fee(
        payment_amount=transfer_description.amount, estimated_fee=route_state.estimated_fee
    )

    lockedtransfer_event = channel.send_lockedtransfer(
        channel_state=channel_state,
        initiator=transfer_description.initiator,
        target=transfer_description.target,
        amount=total_amount,
        message_identifier=message_identifier,
        payment_identifier=transfer_description.payment_identifier,
        expiration=lock_expiration,
        secrethash=transfer_description.secrethash,
        route_states=routes.prune_route_table(
            route_states=route_states, selected_route=route_state
        ),
    )
    return lockedtransfer_event


def handle_secretrequest(
    initiator_state: InitiatorTransferState,
    state_change: ReceiveSecretRequest,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorTransferState]:

    is_message_from_target = (
        state_change.sender == Address(initiator_state.transfer_description.target)
        and state_change.secrethash == initiator_state.transfer_description.secrethash
        and state_change.payment_identifier
        == initiator_state.transfer_description.payment_identifier
    )
    if not is_message_from_target:
        return TransitionResult(initiator_state, list())

    lock = channel.get_lock(
        channel_state.our_state, initiator_state.transfer_description.secrethash
    )

    # This should not ever happen. This task clears itself when the lock is
    # removed.
    assert lock is not None, "channel is does not have the transfer's lock"

    if initiator_state.received_secret_request:
        # A secret request was received earlier, all subsequent are ignored
        # as it might be an attack.
        return TransitionResult(initiator_state, list())

    # transfer_description.amount is the actual payment amount without fees.
    # For the transfer to be valid and the unlock allowed the target must
    # receive at least that amount.
    is_valid_secretrequest = (
        state_change.amount >= initiator_state.transfer_description.amount
        and state_change.expiration == lock.expiration
        and initiator_state.transfer_description.secret != ABSENT_SECRET
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
            recipient=Address(recipient),
            message_identifier=message_identifier,
            secret=transfer_description.secret,
            canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
        )

        initiator_state.transfer_state = "transfer_secret_revealed"
        initiator_state.received_secret_request = True
        return TransitionResult(initiator_state, [revealsecret])
    else:
        initiator_state.received_secret_request = True
        invalid_request = EventInvalidSecretRequest(
            payment_identifier=state_change.payment_identifier,
            intended_amount=initiator_state.transfer_description.amount,
            actual_amount=state_change.amount,
        )
        return TransitionResult(initiator_state, [invalid_request])


def handle_offchain_secretreveal(
    initiator_state: InitiatorTransferState,
    state_change: ReceiveSecretReveal,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorTransferState]]:
    """ Once the next hop proves it knows the secret, the initiator can unlock
    the mediated transfer.

    This will validate the secret, and if valid a new balance proof is sent to
    the next hop with the current lock removed from the pending locks and the
    transferred amount updated.
    """
    iteration: TransitionResult[Optional[InitiatorTransferState]]
    valid_reveal = is_valid_secret_reveal(
        state_change=state_change,
        transfer_secrethash=initiator_state.transfer_description.secrethash,
    )
    sent_by_partner = state_change.sender == channel_state.partner_state.address
    is_channel_open = channel.get_status(channel_state) == ChannelState.STATE_OPENED

    lock = initiator_state.transfer.lock
    expired = channel.is_lock_expired(
        end_state=channel_state.our_state,
        lock=lock,
        block_number=block_number,
        lock_expiration_threshold=lock.expiration,
    )

    if valid_reveal and is_channel_open and sent_by_partner and not expired:
        events = events_for_unlock_lock(
            initiator_state=initiator_state,
            channel_state=channel_state,
            secret=state_change.secret,
            secrethash=state_change.secrethash,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
        iteration = TransitionResult(None, events)
    else:
        events = list()
        iteration = TransitionResult(initiator_state, events)

    return iteration


def handle_onchain_secretreveal(
    initiator_state: InitiatorTransferState,
    state_change: ContractReceiveSecretReveal,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorTransferState]]:
    """ When a secret is revealed on-chain all nodes learn the secret.

    This check the on-chain secret corresponds to the one used by the
    initiator, and if valid a new balance proof is sent to the next hop with
    the current lock removed from the pending locks and the transferred amount
    updated.
    """
    iteration: TransitionResult[Optional[InitiatorTransferState]]
    secret = state_change.secret
    secrethash = initiator_state.transfer_description.secrethash
    is_valid_secret = is_valid_secret_reveal(
        state_change=state_change, transfer_secrethash=secrethash
    )
    is_channel_open = channel.get_status(channel_state) == ChannelState.STATE_OPENED
    is_lock_expired = state_change.block_number > initiator_state.transfer.lock.expiration

    is_lock_unlocked = is_valid_secret and not is_lock_expired

    if is_lock_unlocked:
        channel.register_onchain_secret(
            channel_state=channel_state,
            secret=secret,
            secrethash=secrethash,
            secret_reveal_block_number=state_change.block_number,
        )

    lock = initiator_state.transfer.lock
    expired = channel.is_lock_expired(
        end_state=channel_state.our_state,
        lock=lock,
        block_number=block_number,
        lock_expiration_threshold=lock.expiration,
    )

    if is_lock_unlocked and is_channel_open and not expired:
        events = events_for_unlock_lock(
            initiator_state,
            channel_state,
            state_change.secret,
            state_change.secrethash,
            pseudo_random_generator,
            block_number,
        )
        iteration = TransitionResult(None, events)
    else:
        events = list()
        iteration = TransitionResult(initiator_state, events)

    return iteration


def state_transition(
    initiator_state: InitiatorTransferState,
    state_change: StateChange,
    channel_state: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorTransferState]]:
    if type(state_change) == Block:
        assert isinstance(state_change, Block), MYPY_ANNOTATION
        iteration = handle_block(
            initiator_state, state_change, channel_state, pseudo_random_generator
        )
    elif type(state_change) == ReceiveSecretRequest:
        assert isinstance(state_change, ReceiveSecretRequest), MYPY_ANNOTATION
        iteration = handle_secretrequest(
            initiator_state, state_change, channel_state, pseudo_random_generator
        )
    elif type(state_change) == ReceiveSecretReveal:
        assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
        iteration = handle_offchain_secretreveal(
            initiator_state, state_change, channel_state, pseudo_random_generator, block_number
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
        iteration = handle_onchain_secretreveal(
            initiator_state, state_change, channel_state, pseudo_random_generator, block_number
        )
    else:
        iteration = TransitionResult(initiator_state, list())

    return iteration
