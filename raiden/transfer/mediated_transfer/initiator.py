import random

from raiden.constants import MAXIMUM_PENDING_TRANSFERS
from raiden.settings import DEFAULT_WAIT_BEFORE_LOCK_REMOVAL
from raiden.transfer import channel
from raiden.transfer.architecture import Event, TransitionResult
from raiden.transfer.events import EventPaymentSentFailed, EventPaymentSentSuccess
from raiden.transfer.mediated_transfer.events import (
    CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
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
    CHANNEL_STATE_OPENED,
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
    BlockTimeout,
    ChannelMap,
    List,
    MessageID,
    Optional,
    PaymentAmount,
    Secret,
    SecretHash,
    TokenAmount,
    cast,
)


def events_for_unlock_lock(
        initiator_state: InitiatorTransferState,
        channel_state: NettingChannelState,
        secret: Secret,
        secrethash: SecretHash,
        pseudo_random_generator: random.Random,
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
    )

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

    lock_expiration_threshold = BlockNumber(
        locked_lock.expiration + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL,
    )
    lock_has_expired, _ = channel.is_lock_expired(
        end_state=channel_state.our_state,
        lock=locked_lock,
        block_number=state_change.block_number,
        lock_expiration_threshold=lock_expiration_threshold,
    )

    events: List[Event] = list()

    if lock_has_expired:
        is_channel_open = channel.get_status(channel_state) == CHANNEL_STATE_OPENED
        if is_channel_open:
            expired_lock_events = channel.events_for_expired_lock(
                channel_state=channel_state,
                locked_lock=locked_lock,
                pseudo_random_generator=pseudo_random_generator,
            )
            events.extend(expired_lock_events)

        if initiator_state.received_secret_request:
            reason = 'bad secret request message from target'
        else:
            reason = 'lock expired'

        transfer_description = initiator_state.transfer_description
        payment_identifier = transfer_description.payment_identifier
        # TODO: When we introduce multiple transfers per payment this needs to be
        #       reconsidered. As we would want to try other routes once a route
        #       has failed, and a transfer failing does not mean the entire payment
        #       would have to fail.
        #       Related issue: https://github.com/raiden-network/raiden/issues/2329
        payment_failed = EventPaymentSentFailed(
            payment_network_identifier=transfer_description.payment_network_identifier,
            token_network_identifier=transfer_description.token_network_identifier,
            identifier=payment_identifier,
            target=transfer_description.target,
            reason=reason,
        )
        unlock_failed = EventUnlockFailed(
            identifier=payment_identifier,
            secrethash=initiator_state.transfer_description.secrethash,
            reason=reason,
        )

        lock_exists = channel.lock_exists_in_either_channel_side(
            channel_state=channel_state,
            secrethash=secrethash,
        )

        return TransitionResult(
            # If the lock is either in our state or partner state we keep the
            # task around to wait for the LockExpired messages to sync.
            # Check https://github.com/raiden-network/raiden/issues/3183
            initiator_state if lock_exists else None,
            events + [payment_failed, unlock_failed],
        )
    else:
        return TransitionResult(initiator_state, events)


def get_initial_lock_expiration(
        block_number: BlockNumber,
        reveal_timeout: BlockTimeout,
) -> BlockExpiration:
    """ Returns the expiration used for all hash-time-locks in transfer. """
    return BlockExpiration(block_number + reveal_timeout * 2)


def next_channel_from_routes(
        available_routes: List[RouteState],
        channelidentifiers_to_channels: ChannelMap,
        transfer_amount: TokenAmount,
) -> Optional[NettingChannelState]:
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
        channelidentifiers_to_channels: ChannelMap,
        available_routes: List[RouteState],
        transfer_description: TransferDescriptionWithSecretState,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
) -> TransitionResult[Optional[InitiatorTransferState]]:

    channel_state = next_channel_from_routes(
        available_routes,
        channelidentifiers_to_channels,
        transfer_description.amount,
    )

    events: List[Event] = list()
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
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        lockedtransfer_event = send_lockedtransfer(
            transfer_description=transfer_description,
            channel_state=channel_state,
            message_identifier=message_identifier,
            block_number=block_number,
        )
        assert lockedtransfer_event

        initiator_state = InitiatorTransferState(
            transfer_description=transfer_description,
            channel_identifier=channel_state.identifier,
            transfer=lockedtransfer_event.transfer,
            revealsecret=None,
        )
        events.append(lockedtransfer_event)

    return TransitionResult(initiator_state, events)


def send_lockedtransfer(
        transfer_description: TransferDescriptionWithSecretState,
        channel_state: NettingChannelState,
        message_identifier: MessageID,
        block_number: BlockNumber,
) -> SendLockedTransfer:
    """ Create a mediated transfer using channel. """
    assert channel_state.token_network_identifier == transfer_description.token_network_identifier

    lock_expiration = get_initial_lock_expiration(
        block_number,
        channel_state.reveal_timeout,
    )

    lockedtransfer_event = channel.send_lockedtransfer(
        channel_state,
        transfer_description.initiator,
        transfer_description.target,
        cast(
            PaymentAmount,
            transfer_description.amount,
        ),
        message_identifier,
        transfer_description.payment_identifier,
        lock_expiration,
        transfer_description.secrethash,
    )
    return lockedtransfer_event


def handle_secretrequest(
        initiator_state: InitiatorTransferState,
        state_change: ReceiveSecretRequest,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
) -> TransitionResult[InitiatorTransferState]:

    is_message_from_target = (
        state_change.sender == initiator_state.transfer_description.target and
        state_change.secrethash == initiator_state.transfer_description.secrethash and
        state_change.payment_identifier == initiator_state.transfer_description.payment_identifier
    )

    lock = channel.get_lock(
        channel_state.our_state,
        initiator_state.transfer_description.secrethash,
    )

    already_received_secret_request = initiator_state.received_secret_request

    is_valid_secretrequest = (
        state_change.amount == initiator_state.transfer_description.amount and
        state_change.expiration == lock.expiration
    )

    if already_received_secret_request and is_message_from_target:
        # A secret request was received earlier, all subsequent are ignored
        # as it might be an attack
        iteration = TransitionResult(initiator_state, list())

    elif is_valid_secretrequest and is_message_from_target:
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
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=message_identifier,
            secret=transfer_description.secret,
        )

        initiator_state.revealsecret = revealsecret
        initiator_state.received_secret_request = True
        iteration = TransitionResult(initiator_state, [revealsecret])

    elif not is_valid_secretrequest and is_message_from_target:
        initiator_state.received_secret_request = True
        iteration = TransitionResult(initiator_state, list())

    else:
        iteration = TransitionResult(initiator_state, list())

    return iteration


def handle_offchain_secretreveal(
        initiator_state: InitiatorTransferState,
        state_change: ReceiveSecretReveal,
        channel_state: NettingChannelState,
        pseudo_random_generator: random.Random,
) -> TransitionResult[Optional[InitiatorTransferState]]:
    """ Once the next hop proves it knows the secret, the initiator can unlock
    the mediated transfer.

    This will validate the secret, and if valid a new balance proof is sent to
    the next hop with the current lock removed from the merkle tree and the
    transferred amount updated.
    """
    valid_reveal = is_valid_secret_reveal(
        state_change=state_change,
        transfer_secrethash=initiator_state.transfer_description.secrethash,
        secret=state_change.secret,
    )
    sent_by_partner = state_change.sender == channel_state.partner_state.address
    is_channel_open = channel.get_status(channel_state) == CHANNEL_STATE_OPENED

    if valid_reveal and is_channel_open and sent_by_partner:
        events = events_for_unlock_lock(
            initiator_state=initiator_state,
            channel_state=channel_state,
            secret=state_change.secret,
            secrethash=state_change.secrethash,
            pseudo_random_generator=pseudo_random_generator,
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
) -> TransitionResult[Optional[InitiatorTransferState]]:
    """ When a secret is revealed on-chain all nodes learn the secret.

    This check the on-chain secret corresponds to the one used by the
    initiator, and if valid a new balance proof is sent to the next hop with
    the current lock removed from the merkle tree and the transferred amount
    updated.
    """
    secret = state_change.secret
    secrethash = initiator_state.transfer_description.secrethash
    is_valid_secret = is_valid_secret_reveal(
        state_change=state_change,
        transfer_secrethash=secrethash,
        secret=secret,
    )
    is_channel_open = channel.get_status(channel_state) == CHANNEL_STATE_OPENED
    is_lock_expired = state_change.block_number > initiator_state.transfer.lock.expiration

    is_lock_unlocked = (
        is_valid_secret and
        not is_lock_expired
    )

    if is_lock_unlocked:
        channel.register_onchain_secret(
            channel_state=channel_state,
            secret=secret,
            secrethash=secrethash,
            secret_reveal_block_number=state_change.block_number,
        )

    if is_lock_unlocked and is_channel_open:
        events = events_for_unlock_lock(
            initiator_state,
            channel_state,
            state_change.secret,
            state_change.secrethash,
            pseudo_random_generator,
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
            initiator_state,
            state_change,
            channel_state,
            pseudo_random_generator,
        )
    elif type(state_change) == ReceiveSecretRequest:
        assert isinstance(state_change, ReceiveSecretRequest), MYPY_ANNOTATION
        iteration = handle_secretrequest(
            initiator_state,
            state_change,
            channel_state,
            pseudo_random_generator,
        )
    elif type(state_change) == ReceiveSecretReveal:
        assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
        iteration = handle_offchain_secretreveal(
            initiator_state,
            state_change,
            channel_state,
            pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveSecretReveal:
        assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
        iteration = handle_onchain_secretreveal(
            initiator_state,
            state_change,
            channel_state,
            pseudo_random_generator,
        )
    else:
        iteration = TransitionResult(initiator_state, list())

    return iteration
