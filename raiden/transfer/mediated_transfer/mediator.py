import itertools
import operator
import random
from fractions import Fraction
from typing import Callable

from raiden.exceptions import UndefinedMediationFee
from raiden.transfer import channel, routes, secret_registry
from raiden.transfer.architecture import Event, StateChange, SuccessOrError, TransitionResult
from raiden.transfer.channel import get_balance
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_UNORDERED_QUEUE
from raiden.transfer.mediated_transfer.events import (
    EventUnexpectedSecretReveal,
    EventUnlockClaimFailed,
    EventUnlockClaimSuccess,
    EventUnlockFailed,
    EventUnlockSuccess,
    SendLockedTransfer,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState, Interpolate
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    LockedTransferUnsignedState,
    MediationPairState,
    MediatorTransferState,
    WaitingTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ReceiveLockExpired,
    ReceiveSecretReveal,
    ReceiveTransferRefund,
)
from raiden.transfer.state import (
    ChannelState,
    NettingChannelState,
    get_address_metadata,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal, ReceiveUnlock
from raiden.transfer.utils import is_valid_secret_reveal
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    BlockExpiration,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChannelID,
    Dict,
    List,
    LockType,
    Optional,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    TokenAmount,
    TokenNetworkAddress,
    Tuple,
    Union,
    cast,
    typecheck,
)

STATE_SECRET_KNOWN = (
    "payee_secret_revealed",
    "payee_contract_unlock",
    "payee_balance_proof",
    "payer_secret_revealed",
    "payer_waiting_unlock",
    "payer_balance_proof",
)
STATE_TRANSFER_PAID = ("payee_contract_unlock", "payee_balance_proof", "payer_balance_proof")
# TODO: fix expired state, it is not final
STATE_TRANSFER_FINAL = (
    "payee_contract_unlock",
    "payee_balance_proof",
    "payee_expired",
    "payer_balance_proof",
    "payer_expired",
)


def is_lock_valid(expiration: BlockExpiration, block_number: BlockNumber) -> bool:
    """True if the lock has not expired."""
    return block_number <= BlockNumber(expiration)


def is_safe_to_wait(
    lock_expiration: BlockExpiration, reveal_timeout: BlockTimeout, block_number: BlockNumber
) -> SuccessOrError:
    """True if waiting is safe, i.e. there are more than enough blocks to safely
    unlock on chain.
    """
    # reveal timeout will not ever be larger than the lock_expiration otherwise
    # the expected block_number is negative
    assert block_number > 0, "block_number must be larger than zero"
    assert reveal_timeout > 0, "reveal_timeout must be larger than zero"
    assert lock_expiration > reveal_timeout, "lock_expiration must be larger than reveal_timeout"

    lock_timeout = lock_expiration - block_number

    # A node may wait for a new balance proof while there are reveal_timeout
    # blocks left, at that block and onwards it is not safe to wait.
    if lock_timeout > reveal_timeout:
        return SuccessOrError()

    return SuccessOrError(
        f"lock timeout is unsafe."
        f" timeout must be larger than {reveal_timeout}, but it is {lock_timeout}."
        f" expiration: {lock_expiration} block_number: {block_number}"
    )


def is_send_transfer_almost_equal(
    send_channel: NettingChannelState,  # pylint: disable=unused-argument
    send: LockedTransferUnsignedState,
    received: LockedTransferSignedState,
) -> bool:
    """True if both transfers are for the same mediated transfer."""
    # The only thing that may change is the direction of the transfer
    return (
        send.payment_identifier == received.payment_identifier
        and send.token == received.token
        # FIXME: Checking the transferred amount would make a lot of sense, but
        #        this is hard to do precisely without larger changes to the
        #        codebase. With the uncertainty about how we want to deal with
        #        refunds and backtracking in the long term, this check is
        #        skipped for now.
        # and send.lock.amount == received.lock.amount - send_channel.fee_schedule.flat
        and send.lock.expiration == received.lock.expiration
        and send.lock.secrethash == received.lock.secrethash
        and send.initiator == received.initiator
        and send.target == received.target
    )


def has_secret_registration_started(
    channel_states: List[NettingChannelState],
    transfers_pair: List[MediationPairState],
    secrethash: SecretHash,
) -> bool:
    # If it's known the secret is registered on-chain, the node should not send
    # a new transaction. Note there is a race condition:
    #
    # - Node B learns the secret on-chain, sends a secret reveal to A
    # - Node A receives the secret reveal off-chain prior to the event for the
    #   secret registration, if the lock is in the danger zone A will try to
    #   register the secret on-chain, because from its perspective the secret
    #   is not there yet.
    is_secret_registered_onchain = any(
        channel.is_secret_known_onchain(payer_channel.partner_state, secrethash)
        for payer_channel in channel_states
    )
    has_pending_transaction = any(
        pair.payer_state == "payer_waiting_secret_reveal" for pair in transfers_pair
    )
    return is_secret_registered_onchain or has_pending_transaction


def get_payee_channel(
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    transfer_pair: MediationPairState,
) -> Optional[NettingChannelState]:
    """Returns the payee channel of a given transfer pair or None if it's not found"""
    payee_channel_identifier = transfer_pair.payee_transfer.balance_proof.channel_identifier
    return channelidentifiers_to_channels.get(payee_channel_identifier)


def get_payer_channel(
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    transfer_pair: MediationPairState,
) -> Optional[NettingChannelState]:
    """Returns the payer channel of a given transfer pair or None if it's not found"""
    payer_channel_identifier = transfer_pair.payer_transfer.balance_proof.channel_identifier
    return channelidentifiers_to_channels.get(payer_channel_identifier)


def get_pending_transfer_pairs(
    transfers_pair: List[MediationPairState],
) -> List[MediationPairState]:
    """Return the transfer pairs that are not at a final state."""
    pending_pairs = [
        pair
        for pair in transfers_pair
        if pair.payee_state not in STATE_TRANSFER_FINAL
        or pair.payer_state not in STATE_TRANSFER_FINAL
    ]
    return pending_pairs


def find_intersection(
    fee_func: Interpolate, line: Callable[[int], Fraction]
) -> Optional[Fraction]:
    """Returns the x value where both functions intersect

    `fee_func` is a piecewise linear function while `line` is a straight line
    and takes the one of fee_func's indexes as argument.

    Returns `None` if there is no intersection within `fee_func`s domain, which
    indicates a lack of capacity.
    """
    i = 0
    y = fee_func.y_list[i]
    compare = operator.lt if y < line(i) else operator.gt
    while compare(y, line(i)):
        i += 1
        if i == len(fee_func.x_list):
            # Not enough capacity to send
            return None
        y = fee_func.y_list[i]

    # We found the linear section where the solution is. Now interpolate!
    x1 = fee_func.x_list[i - 1]
    x2 = fee_func.x_list[i]
    yf1 = fee_func.y_list[i - 1]
    yf2 = fee_func.y_list[i]
    yl1 = line(i - 1)
    yl2 = line(i)
    return (yl1 - yf1) * (x2 - x1) / ((yf2 - yf1) - (yl2 - yl1)) + x1


def get_amount_without_fees(
    amount_with_fees: PaymentWithFeeAmount,
    channel_in: NettingChannelState,
    channel_out: NettingChannelState,
) -> Optional[PaymentWithFeeAmount]:
    """Return the amount after fees are taken."""

    balance_in = get_balance(channel_in.our_state, channel_in.partner_state)
    balance_out = get_balance(channel_out.our_state, channel_out.partner_state)
    receivable = TokenAmount(
        channel_in.our_total_deposit + channel_in.partner_total_deposit - balance_in
    )
    assert (
        channel_in.fee_schedule.cap_fees == channel_out.fee_schedule.cap_fees
    ), "Both channels must have the same cap_fees setting for the same mediator."
    try:
        fee_func = FeeScheduleState.mediation_fee_func(
            schedule_in=channel_in.fee_schedule,
            schedule_out=channel_out.fee_schedule,
            balance_in=balance_in,
            balance_out=balance_out,
            receivable=receivable,
            amount_with_fees=amount_with_fees,
            cap_fees=channel_in.fee_schedule.cap_fees,
        )
        amount_without_fees = find_intersection(
            fee_func, lambda i: amount_with_fees - fee_func.x_list[i]
        )
    except UndefinedMediationFee:
        return None

    if amount_without_fees is None:
        # Insufficient capacity
        return None
    if amount_without_fees <= 0:
        # The node can't cover its mediations fees from the transferred amount.
        return None

    return PaymentWithFeeAmount(int(round(amount_without_fees)))


def sanity_check(
    state: MediatorTransferState,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
) -> None:
    """Check invariants that must hold."""

    # if a transfer is paid we must know the secret
    all_transfers_states = itertools.chain(
        (pair.payee_state for pair in state.transfers_pair),
        (pair.payer_state for pair in state.transfers_pair),
    )
    if any(state in STATE_TRANSFER_PAID for state in all_transfers_states):
        assert state.secret is not None, "Mediator's state must have secret"

    # the "transitivity" for these values is checked below as part of
    # almost_equal check
    if state.transfers_pair:
        first_pair = state.transfers_pair[0]
        assert (
            state.secrethash == first_pair.payer_transfer.lock.secrethash
        ), "Secret hash mismatch"

    for pair in state.transfers_pair:
        payee_channel = get_payee_channel(
            channelidentifiers_to_channels=channelidentifiers_to_channels, transfer_pair=pair
        )

        # Channel could have been removed
        if not payee_channel:
            continue

        assert is_send_transfer_almost_equal(
            send_channel=payee_channel, send=pair.payee_transfer, received=pair.payer_transfer
        ), "Payee and payer transfers are too different"
        assert pair.payer_state in pair.valid_payer_states, "payer_state not in valid payer states"
        assert pair.payee_state in pair.valid_payee_states, "payee_state not in valid payee states"

    for original, refund in zip(state.transfers_pair[:-1], state.transfers_pair[1:]):
        assert original.payee_address == refund.payer_address, "payee/payer address mismatch"
        payer_channel = get_payer_channel(
            channelidentifiers_to_channels=channelidentifiers_to_channels, transfer_pair=refund
        )

        # Channel could have been removed
        if not payer_channel:
            continue

        transfer_sent = original.payee_transfer
        transfer_received = refund.payer_transfer
        assert is_send_transfer_almost_equal(
            send_channel=payer_channel, send=transfer_sent, received=transfer_received
        ), "Payee and payer transfers are too different (refund)"

    if state.waiting_transfer and state.transfers_pair:
        last_transfer_pair = state.transfers_pair[-1]
        payee_channel = get_payee_channel(
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            transfer_pair=last_transfer_pair,
        )
        # Channel could have been removed
        if payee_channel:
            transfer_sent = last_transfer_pair.payee_transfer
            transfer_received = state.waiting_transfer.transfer

            assert is_send_transfer_almost_equal(
                send_channel=payee_channel, send=transfer_sent, received=transfer_received
            ), "Payee and payer transfers are too different (waiting transfer)"


def clear_if_finalized(
    iteration: TransitionResult,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
) -> TransitionResult[Optional[MediatorTransferState]]:
    """Clear the mediator task if all the locks have been finalized.

    A lock is considered finalized if it has been removed from the pending locks
    offchain, either because the transfer was unlocked or expired, or because the
    channel was settled on chain and therefore the channel is removed."""
    state = cast(MediatorTransferState, iteration.new_state)

    if state is None:
        return iteration  # type: ignore

    # Only clear the task if all channels have the lock cleared.
    secrethash = state.secrethash
    for pair in state.transfers_pair:
        payer_channel = get_payer_channel(channelidentifiers_to_channels, pair)
        if payer_channel and channel.is_lock_pending(payer_channel.partner_state, secrethash):
            return iteration

        payee_channel = get_payee_channel(channelidentifiers_to_channels, pair)
        if payee_channel and channel.is_lock_pending(payee_channel.our_state, secrethash):
            return iteration

    if state.waiting_transfer:
        waiting_transfer = state.waiting_transfer.transfer
        waiting_channel_identifier = waiting_transfer.balance_proof.channel_identifier
        waiting_channel = channelidentifiers_to_channels.get(waiting_channel_identifier)

        if waiting_channel and channel.is_lock_pending(waiting_channel.partner_state, secrethash):
            return iteration

    return TransitionResult(None, iteration.events)


def forward_transfer_pair(
    payer_transfer: LockedTransferSignedState,
    payer_channel: NettingChannelState,
    payee_channel: NettingChannelState,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> Tuple[Optional[MediationPairState], List[Event]]:
    """Given a payer transfer tries the given route to proceed with the mediation.

    Args:
        payer_transfer: The transfer received from the payer_channel.
        channelidentifiers_to_channels: All the channels available for this
            transfer.

        pseudo_random_generator: Number generator to generate a message id.
        block_number: The current block number.
    """

    amount_after_fees = get_amount_without_fees(
        amount_with_fees=payer_transfer.lock.amount,
        channel_in=payer_channel,
        channel_out=payee_channel,
    )
    if not amount_after_fees:
        return None, []

    lock_timeout = BlockTimeout(payer_transfer.lock.expiration - block_number)
    safe_to_use_channel = channel.is_channel_usable_for_mediation(
        channel_state=payee_channel, transfer_amount=amount_after_fees, lock_timeout=lock_timeout
    )

    if not safe_to_use_channel:
        return None, []

    assert payee_channel.settle_timeout >= lock_timeout, "settle_timeout must be >= lock_timeout"

    message_identifier = message_identifier_from_prng(pseudo_random_generator)

    recipient_address = payee_channel.partner_state.address
    recipient_metadata = get_address_metadata(recipient_address, payer_transfer.route_states)
    lockedtransfer_event = channel.send_lockedtransfer(
        channel_state=payee_channel,
        initiator=payer_transfer.initiator,
        target=payer_transfer.target,
        amount=amount_after_fees,
        message_identifier=message_identifier,
        payment_identifier=payer_transfer.payment_identifier,
        expiration=payer_transfer.lock.expiration,
        secret=payer_transfer.secret,
        secrethash=payer_transfer.lock.secrethash,
        route_states=payer_transfer.route_states,
        recipient_metadata=recipient_metadata,
        previous_metadata=payer_transfer.metadata,
    )
    mediated_events: List[Event] = [lockedtransfer_event]

    # create transfer pair
    transfer_pair = MediationPairState(
        payer_transfer=payer_transfer,
        payee_address=payee_channel.partner_state.address,
        payee_transfer=lockedtransfer_event.transfer,
    )

    return transfer_pair, mediated_events


def set_offchain_secret(
    state: MediatorTransferState,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    secret: Secret,
    secrethash: SecretHash,
) -> List[Event]:
    """Set the secret to all mediated transfers."""
    state.secret = secret

    for pair in state.transfers_pair:
        payer_channel = channelidentifiers_to_channels.get(
            pair.payer_transfer.balance_proof.channel_identifier
        )
        if payer_channel:
            channel.register_offchain_secret(payer_channel, secret, secrethash)

        payee_channel = channelidentifiers_to_channels.get(
            pair.payee_transfer.balance_proof.channel_identifier
        )
        if payee_channel:
            channel.register_offchain_secret(payee_channel, secret, secrethash)

    # The secret should never be revealed if `waiting_transfer` is not None.
    # For this to happen this node must have received a transfer, which it did
    # *not* mediate, and nevertheless the secret was revealed.
    #
    # This can only be possible if the initiator reveals the secret without the
    # target's secret request, or if the node which sent the `waiting_transfer`
    # has sent another transfer which reached the target (meaning someone along
    # the path will lose tokens).
    if state.waiting_transfer:
        payer_channel = channelidentifiers_to_channels.get(
            state.waiting_transfer.transfer.balance_proof.channel_identifier
        )
        if payer_channel:
            channel.register_offchain_secret(payer_channel, secret, secrethash)

        unexpected_reveal = EventUnexpectedSecretReveal(
            secrethash=secrethash, reason="The mediator has a waiting transfer."
        )
        return [unexpected_reveal]

    return []


def set_onchain_secret(
    state: MediatorTransferState,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    secret: Secret,
    secrethash: SecretHash,
    block_number: BlockNumber,
) -> List[Event]:
    """Set the secret to all mediated transfers.

    The secret should have been learned from the secret registry.
    """
    state.secret = secret

    for pair in state.transfers_pair:
        payer_channel = channelidentifiers_to_channels.get(
            pair.payer_transfer.balance_proof.channel_identifier
        )
        if payer_channel:
            channel.register_onchain_secret(payer_channel, secret, secrethash, block_number)

        payee_channel = channelidentifiers_to_channels.get(
            pair.payee_transfer.balance_proof.channel_identifier
        )
        if payee_channel:
            channel.register_onchain_secret(
                channel_state=payee_channel,
                secret=secret,
                secrethash=secrethash,
                secret_reveal_block_number=block_number,
            )

    # Like the off-chain secret reveal, the secret should never be revealed
    # on-chain if there is a waiting transfer.
    if state.waiting_transfer:
        payer_channel = channelidentifiers_to_channels.get(
            state.waiting_transfer.transfer.balance_proof.channel_identifier
        )
        if payer_channel:
            channel.register_onchain_secret(
                channel_state=payer_channel,
                secret=secret,
                secrethash=secrethash,
                secret_reveal_block_number=block_number,
            )

        unexpected_reveal = EventUnexpectedSecretReveal(
            secrethash=secrethash, reason="The mediator has a waiting transfer."
        )
        return [unexpected_reveal]

    return []


def set_offchain_reveal_state(
    transfers_pair: List[MediationPairState], payee_address: Address
) -> None:
    """Set the state of a transfer *sent* to a payee."""
    for pair in transfers_pair:
        if pair.payee_address == payee_address:
            pair.payee_state = "payee_secret_revealed"


def events_for_expired_pairs(
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    transfers_pair: List[MediationPairState],
    waiting_transfer: Optional[WaitingTransferState],
    block_number: BlockNumber,
) -> List[Event]:
    """Informational events for expired locks."""
    pending_transfers_pairs = get_pending_transfer_pairs(transfers_pair)

    events: List[Event] = []
    for pair in pending_transfers_pairs:
        payer_balance_proof = pair.payer_transfer.balance_proof
        payer_channel = channelidentifiers_to_channels.get(payer_balance_proof.channel_identifier)
        if not payer_channel:
            continue

        has_payer_transfer_expired = channel.is_transfer_expired(
            transfer=pair.payer_transfer, affected_channel=payer_channel, block_number=block_number
        )

        if has_payer_transfer_expired:
            # For safety, the correct behavior is:
            #
            # - If the payee has been paid, then the payer must pay too.
            #
            #   And the corollary:
            #
            # - If the payer transfer has expired, then the payee transfer must
            #   have expired too.
            #
            # The problem is that this corollary cannot be asserted. If a user
            # is running Raiden without a monitoring service, then it may go
            # offline after having paid a transfer to a payee, but without
            # getting a balance proof of the payer, and once it comes back
            # online the transfer may have expired.
            #
            # assert pair.payee_state == 'payee_expired'

            pair.payer_state = "payer_expired"
            unlock_claim_failed = EventUnlockClaimFailed(
                pair.payer_transfer.payment_identifier,
                pair.payer_transfer.lock.secrethash,
                "lock expired",
            )
            events.append(unlock_claim_failed)

    if waiting_transfer:
        expiration_threshold = channel.get_receiver_expiration_threshold(
            waiting_transfer.transfer.lock.expiration
        )
        should_waiting_transfer_expire = (
            waiting_transfer.state != "expired" and expiration_threshold <= block_number
        )
        if should_waiting_transfer_expire:
            waiting_transfer.state = "expired"
            unlock_claim_failed = EventUnlockClaimFailed(
                waiting_transfer.transfer.payment_identifier,
                waiting_transfer.transfer.lock.secrethash,
                "lock expired",
            )
            events.append(unlock_claim_failed)

    return events


def events_for_secretreveal(
    transfers_pair: List[MediationPairState],
    secret: Secret,
    pseudo_random_generator: random.Random,
) -> List[Event]:
    """Reveal the secret off-chain.

    The secret is revealed off-chain even if there is a pending transaction to
    reveal it on-chain, this allows the unlock to happen off-chain, which is
    faster.

    This node is named N, suppose there is a mediated transfer with two refund
    transfers, one from B and one from C:

        A-N-B...B-N-C..C-N-D

    Under normal operation N will first learn the secret from D, then reveal to
    C, wait for C to inform the secret is known before revealing it to B, and
    again wait for B before revealing the secret to A.

    If B somehow sent a reveal secret before C and D, then the secret will be
    revealed to A, but not C and D, meaning the secret won't be propagated
    forward. Even if D sent a reveal secret at about the same time, the secret
    will only be revealed to B upon confirmation from C.

    If the proof doesn't arrive in time and the lock's expiration is at risk, N
    won't lose tokens since it knows the secret can go on-chain at any time.
    """

    events: List[Event] = []
    for pair in reversed(transfers_pair):
        payee_knows_secret = pair.payee_state in STATE_SECRET_KNOWN
        payer_knows_secret = pair.payer_state in STATE_SECRET_KNOWN
        is_transfer_pending = pair.payer_state == "payer_pending"

        should_send_secret = payee_knows_secret and not payer_knows_secret and is_transfer_pending

        if should_send_secret:
            message_identifier = message_identifier_from_prng(pseudo_random_generator)
            pair.payer_state = "payer_secret_revealed"
            payer_transfer = pair.payer_transfer
            revealsecret = SendSecretReveal(
                recipient=payer_transfer.balance_proof.sender,
                recipient_metadata=payer_transfer.payer_address_metadata,
                message_identifier=message_identifier,
                secret=secret,
                canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
            )

            events.append(revealsecret)

    return events


def events_for_balanceproof(
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    transfers_pair: List[MediationPairState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    secret: Secret,
    secrethash: SecretHash,
) -> List[Event]:
    """While it's safe do the off-chain unlock."""

    events: List[Event] = []
    for pair in reversed(transfers_pair):
        payee_knows_secret = pair.payee_state in STATE_SECRET_KNOWN
        payee_payed = pair.payee_state in STATE_TRANSFER_PAID

        payee_channel = get_payee_channel(channelidentifiers_to_channels, pair)
        payee_channel_open = (
            payee_channel and channel.get_status(payee_channel) == ChannelState.STATE_OPENED
        )

        payer_channel = get_payer_channel(channelidentifiers_to_channels, pair)

        # The mediator must not send to the payee a balance proof if the lock
        # is in the danger zone, because the payer may not do the same and the
        # on-chain unlock may fail. If the lock is nearing it's expiration
        # block, then on-chain unlock should be done, and if successful it can
        # be unlocked off-chain.
        is_safe_to_send_balanceproof = False
        if payer_channel:
            is_safe_to_send_balanceproof = is_safe_to_wait(
                pair.payer_transfer.lock.expiration, payer_channel.reveal_timeout, block_number
            ).ok

        should_send_balanceproof_to_payee = (
            payee_channel_open
            and payee_knows_secret
            and not payee_payed
            and is_safe_to_send_balanceproof
        )

        if should_send_balanceproof_to_payee:
            # At this point we are sure that payee_channel exists due to the
            # payee_channel_open check above. So let mypy know about this
            assert payee_channel, MYPY_ANNOTATION
            pair.payee_state = "payee_balance_proof"

            message_identifier = message_identifier_from_prng(pseudo_random_generator)
            recipient_address = pair.payee_address
            recipient_metadata = get_address_metadata(
                recipient_address, pair.payee_transfer.route_states
            )
            unlock_lock = channel.send_unlock(
                channel_state=payee_channel,
                message_identifier=message_identifier,
                payment_identifier=pair.payee_transfer.payment_identifier,
                secret=secret,
                secrethash=secrethash,
                block_number=block_number,
                recipient_metadata=recipient_metadata,
            )

            unlock_success = EventUnlockSuccess(
                pair.payer_transfer.payment_identifier, pair.payer_transfer.lock.secrethash
            )
            events.append(unlock_lock)
            events.append(unlock_success)

    return events


def events_for_onchain_secretreveal_if_dangerzone(
    channelmap: Dict[ChannelID, NettingChannelState],
    secrethash: SecretHash,
    transfers_pair: List[MediationPairState],
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> List[Event]:
    """Reveal the secret on-chain if the lock enters the unsafe region and the
    secret is not yet on-chain.
    """
    events: List[Event] = []

    all_payer_channels = []
    for pair in transfers_pair:
        channel_state = get_payer_channel(channelmap, pair)
        if channel_state:
            all_payer_channels.append(channel_state)

    transaction_sent = has_secret_registration_started(
        all_payer_channels, transfers_pair, secrethash
    )

    # Only consider the transfers which have a pair. This means if we have a
    # waiting transfer and for some reason the node knows the secret, it will
    # not try to register it. Otherwise it would be possible for an attacker to
    # reveal the secret late, just to force the node to send an unnecessary
    # transaction.

    for pair in get_pending_transfer_pairs(transfers_pair):
        payer_channel = get_payer_channel(channelmap, pair)
        if not payer_channel:
            continue

        lock = pair.payer_transfer.lock

        safe_to_wait = is_safe_to_wait(lock.expiration, payer_channel.reveal_timeout, block_number)

        secret_known = channel.is_secret_known(
            payer_channel.partner_state, pair.payer_transfer.lock.secrethash
        )

        if not safe_to_wait and secret_known:
            pair.payer_state = "payer_waiting_secret_reveal"

            if not transaction_sent:
                secret = channel.get_secret(payer_channel.partner_state, lock.secrethash)
                assert secret, "the secret should be known at this point"

                reveal_events = secret_registry.events_for_onchain_secretreveal(
                    channel_state=payer_channel,
                    secret=secret,
                    expiration=lock.expiration,
                    block_hash=block_hash,
                )
                events.extend(reveal_events)

                transaction_sent = True

    return events


def events_for_onchain_secretreveal_if_closed(
    channelmap: Dict[ChannelID, NettingChannelState],
    transfers_pair: List[MediationPairState],
    secret: Secret,
    secrethash: SecretHash,
    block_hash: BlockHash,
) -> List[Event]:
    """Register the secret on-chain if the payer channel is already closed and
    the mediator learned the secret off-chain.

    Balance proofs are not exchanged for closed channels, so there is no reason
    to wait for the unsafe region to register secret.

    Note:

        If the secret is learned before the channel is closed, then the channel
        will register the secrets in bulk, not the transfer.
    """
    events: List[Event] = []

    all_payer_channels = []
    for pair in transfers_pair:
        channel_state = get_payer_channel(channelmap, pair)
        if channel_state:
            all_payer_channels.append(channel_state)
    transaction_sent = has_secret_registration_started(
        all_payer_channels, transfers_pair, secrethash
    )

    # Just like the case for entering the danger zone, this will only consider
    # the transfers which have a pair.

    for pending_pair in get_pending_transfer_pairs(transfers_pair):
        payer_channel = get_payer_channel(channelmap, pending_pair)
        # Don't register the secret on-chain if the channel is open or settled
        if payer_channel and channel.get_status(payer_channel) == ChannelState.STATE_CLOSED:
            pending_pair.payer_state = "payer_waiting_secret_reveal"

            if not transaction_sent:
                partner_state = payer_channel.partner_state

                lock = channel.get_lock(partner_state, secrethash)

                # The mediator task lives as long as there are any pending
                # locks, it may be the case that some of the transfer_pairs got
                # resolved off-chain, but others didn't. For this reason we
                # must check if the lock is still part of the channel
                if lock:
                    reveal_events = secret_registry.events_for_onchain_secretreveal(
                        channel_state=payer_channel,
                        secret=secret,
                        expiration=lock.expiration,
                        block_hash=block_hash,
                    )
                    events.extend(reveal_events)
                    transaction_sent = True

    return events


def events_to_remove_expired_locks(
    mediator_state: MediatorTransferState,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    block_number: BlockNumber,
    pseudo_random_generator: random.Random,
) -> List[Event]:
    """Clear the channels which have expired locks.

    This only considers the *sent* transfers, received transfers can only be
    updated by the partner.
    """
    events: List[Event] = []

    if not mediator_state.transfers_pair:
        return events

    # This is the initial transfer we received for this payment. Here all the relevant
    # route and address-metadata is present
    initial_payer_transfer: LockedTransferSignedState = mediator_state.transfers_pair[
        0
    ].payer_transfer
    for transfer_pair in mediator_state.transfers_pair:
        balance_proof = transfer_pair.payee_transfer.balance_proof
        channel_identifier = balance_proof.channel_identifier
        channel_state = channelidentifiers_to_channels.get(channel_identifier)
        if not channel_state:
            continue

        secrethash = mediator_state.secrethash
        lock: Union[None, LockType] = None
        if secrethash in channel_state.our_state.secrethashes_to_lockedlocks:
            assert (
                secrethash not in channel_state.our_state.secrethashes_to_unlockedlocks
            ), "Locks for secrethash are already unlocked"
            lock = channel_state.our_state.secrethashes_to_lockedlocks.get(secrethash)
        elif secrethash in channel_state.our_state.secrethashes_to_unlockedlocks:
            lock = channel_state.our_state.secrethashes_to_unlockedlocks.get(secrethash)
        if lock:
            lock_expiration_threshold = channel.get_sender_expiration_threshold(lock.expiration)
            has_lock_expired = channel.is_lock_expired(
                end_state=channel_state.our_state,
                lock=lock,
                block_number=block_number,
                lock_expiration_threshold=lock_expiration_threshold,
            )

            is_channel_open = channel.get_status(channel_state) == ChannelState.STATE_OPENED

            # The initial_payer_transfer is the initial transfer we received from a previous hop,
            # so there we have all metadata that was passed on to other nodes already
            # present
            payee_address_metadata = get_address_metadata(
                transfer_pair.payee_address, initial_payer_transfer.route_states
            )
            if has_lock_expired and is_channel_open:
                transfer_pair.payee_state = "payee_expired"
                expired_lock_events = channel.send_lock_expired(
                    channel_state=channel_state,
                    locked_lock=lock,
                    pseudo_random_generator=pseudo_random_generator,
                    recipient_metadata=payee_address_metadata,
                )
                events.extend(expired_lock_events)

                unlock_failed = EventUnlockFailed(
                    transfer_pair.payee_transfer.payment_identifier,
                    transfer_pair.payee_transfer.lock.secrethash,
                    "lock expired",
                )
                events.append(unlock_failed)

    return events


def secret_learned(
    state: MediatorTransferState,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    block_hash: BlockHash,
    secret: Secret,
    secrethash: SecretHash,
    payee_address: Address,
) -> TransitionResult[MediatorTransferState]:
    """Unlock the payee lock, reveal the lock to the payer, and if necessary
    register the secret on-chain.
    """
    secret_reveal_events = set_offchain_secret(
        state, channelidentifiers_to_channels, secret, secrethash
    )

    set_offchain_reveal_state(state.transfers_pair, payee_address)

    onchain_secret_reveal = events_for_onchain_secretreveal_if_closed(
        channelmap=channelidentifiers_to_channels,
        transfers_pair=state.transfers_pair,
        secret=secret,
        secrethash=secrethash,
        block_hash=block_hash,
    )

    offchain_secret_reveal = events_for_secretreveal(
        state.transfers_pair, secret, pseudo_random_generator
    )

    balance_proof = events_for_balanceproof(
        channelidentifiers_to_channels,
        state.transfers_pair,
        pseudo_random_generator,
        block_number,
        secret,
        secrethash,
    )

    events = secret_reveal_events + offchain_secret_reveal + balance_proof + onchain_secret_reveal
    iteration = TransitionResult(state, events)

    return iteration


def mediate_transfer(
    state: MediatorTransferState,
    payer_channel: NettingChannelState,
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
    payer_transfer: LockedTransferSignedState,
    block_number: BlockNumber,
) -> TransitionResult[MediatorTransferState]:
    """Try a new route or fail back to a refund.

    The mediator can safely try a new route knowing that the tokens from
    payer_transfer will cover the expenses of the mediation. If there is no
    route available that may be used at the moment of the call the mediator may
    send a refund back to the payer, allowing the payer to try a different
    route.
    """
    assert (
        payer_channel.partner_state.address == payer_transfer.balance_proof.sender
    ), "Transfer must be signed by sender"

    our_address = payer_channel.our_state.address
    # Makes sure we filter routes that have already been used.
    #
    # So in a setup like this, we want to make sure that node 2, having tried to
    # route the transfer through 3 will also try 5 before sending it backwards to 1
    #
    # 1 -> 2 -> 3 -> 4
    #      v         ^
    #      5 -> 6 -> 7
    candidate_route_states = routes.filter_acceptable_routes(
        route_states=state.routes,
        blacklisted_channel_ids=state.refunded_channels,
        addresses_to_channel=addresses_to_channel,
        token_network_address=payer_channel.token_network_address,
        our_address=our_address,
    )

    # Mediate through the first valid route
    for route_state in candidate_route_states:
        next_hop = route_state.hop_after(our_address)
        if not next_hop:
            continue
        target_token_network = route_state.swaps.get(
            our_address, payer_channel.token_network_address
        )
        payee_channel = addresses_to_channel.get((target_token_network, next_hop))
        if not payee_channel:
            continue

        mediation_transfer_pair, mediation_events = forward_transfer_pair(
            payer_transfer=payer_transfer,
            payer_channel=payer_channel,
            payee_channel=payee_channel,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
        if mediation_transfer_pair is not None:
            state.transfers_pair.append(mediation_transfer_pair)
            return TransitionResult(state, mediation_events)

    # Could not mediate, wait for a later time to do so
    state.waiting_transfer = WaitingTransferState(payer_transfer)
    return TransitionResult(state, [])


def handle_init(
    state_change: ActionInitMediator,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[Optional[MediatorTransferState]]:
    from_hop = state_change.from_hop
    from_transfer = state_change.from_transfer
    payer_channel = channelidentifiers_to_channels.get(from_hop.channel_identifier)

    # There is no corresponding channel for the message, ignore it
    if not payer_channel:
        return TransitionResult(None, [])

    mediator_state = MediatorTransferState(
        secrethash=from_transfer.lock.secrethash, routes=state_change.candidate_route_states
    )

    is_valid, events, _ = channel.handle_receive_lockedtransfer(
        payer_channel,
        from_transfer,
        recipient_metadata=state_change.from_transfer.payer_address_metadata,
    )
    if not is_valid:
        # If the balance proof is not valid, do *not* create a task. Otherwise it's
        # possible for an attacker to send multiple invalid transfers, and increase
        # the memory usage of this Node.
        return TransitionResult(None, events)

    iteration = mediate_transfer(
        state=mediator_state,
        payer_channel=payer_channel,
        addresses_to_channel=addresses_to_channel,
        pseudo_random_generator=pseudo_random_generator,
        payer_transfer=from_transfer,
        block_number=block_number,
    )

    events.extend(iteration.events)
    return TransitionResult(iteration.new_state, events)


def handle_block(
    mediator_state: MediatorTransferState,
    state_change: Block,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
) -> TransitionResult[MediatorTransferState]:
    """After Raiden learns about a new block this function must be called to
    handle expiration of the hash time locks.
    Args:
        state: The current state.
    Return:
        TransitionResult: The resulting iteration
    """

    mediate_events: List[Event] = []
    if mediator_state.waiting_transfer:
        secrethash = mediator_state.waiting_transfer.transfer.lock.secrethash
        payer_channel = channelidentifiers_to_channels.get(
            mediator_state.waiting_transfer.transfer.balance_proof.channel_identifier
        )
        if payer_channel is not None:
            # If the transfer is waiting, because its expiry was later than the settlement timeout
            # of the channel, we can retry the mediation on a new block. The call to
            # `mediate_transfer` will re-evaluate the timeouts and mediate if possible.
            mediation_attempt = mediate_transfer(
                state=mediator_state,
                payer_channel=payer_channel,
                addresses_to_channel=addresses_to_channel,
                pseudo_random_generator=pseudo_random_generator,
                payer_transfer=mediator_state.waiting_transfer.transfer,
                block_number=state_change.block_number,
            )
            mediator_state = mediation_attempt.new_state
            mediate_events = mediation_attempt.events
            success_filter = lambda event: (
                isinstance(event, SendLockedTransfer)
                and event.transfer.lock.secrethash == secrethash
            )

            mediation_happened = any(filter(success_filter, mediate_events))
            if mediation_happened:
                mediator_state.waiting_transfer = None

    expired_locks_events = events_to_remove_expired_locks(
        mediator_state=mediator_state,
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        block_number=state_change.block_number,
        pseudo_random_generator=pseudo_random_generator,
    )

    secret_reveal_events = events_for_onchain_secretreveal_if_dangerzone(
        channelmap=channelidentifiers_to_channels,
        secrethash=mediator_state.secrethash,
        transfers_pair=mediator_state.transfers_pair,
        block_number=state_change.block_number,
        block_hash=state_change.block_hash,
    )

    unlock_fail_events = events_for_expired_pairs(
        channelidentifiers_to_channels=channelidentifiers_to_channels,
        transfers_pair=mediator_state.transfers_pair,
        waiting_transfer=mediator_state.waiting_transfer,
        block_number=state_change.block_number,
    )

    iteration = TransitionResult(
        mediator_state,
        mediate_events + unlock_fail_events + secret_reveal_events + expired_locks_events,
    )

    return iteration


def handle_refundtransfer(
    mediator_state: MediatorTransferState,
    mediator_state_change: ReceiveTransferRefund,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[MediatorTransferState]:
    """Validate and handle a ReceiveTransferRefund mediator_state change.
    A node might participate in mediated transfer more than once because of
    refund transfers, e.g. A-B-C-B-D-T, B tried to mediate the transfer through
    C, which didn't have an available route to proceed and refunds B, at this
    point B is part of the path again and will try a new partner to proceed
    with the mediation through D, D finally reaches the target T.
    In the above scenario B has two pairs of payer and payee transfers:
        payer:A payee:C from the first SendLockedTransfer
        payer:C payee:D from the following SendRefundTransfer
    Args:
        mediator_state: Current mediator_state.
        mediator_state_change: The mediator_state change.
    Returns:
        TransitionResult: The resulting iteration.
    """
    events: List[Event] = []
    if mediator_state.secret is None:
        # The last sent transfer is the only one that may be refunded, all the
        # previous ones are refunded already.
        transfer_pair = mediator_state.transfers_pair[-1]
        payee_transfer = transfer_pair.payee_transfer
        payer_transfer = mediator_state_change.transfer
        channel_identifier = payer_transfer.balance_proof.channel_identifier
        payer_channel = channelidentifiers_to_channels.get(channel_identifier)
        if not payer_channel:
            return TransitionResult(mediator_state, [])

        is_valid, channel_events, _ = channel.handle_refundtransfer(
            received_transfer=payee_transfer,
            channel_state=payer_channel,
            refund=mediator_state_change,
        )
        if not is_valid:
            return TransitionResult(mediator_state, channel_events)

        mediator_state.refunded_channels.append(
            payer_channel.canonical_identifier.channel_identifier
        )
        iteration = mediate_transfer(
            state=mediator_state,
            payer_channel=payer_channel,
            addresses_to_channel=addresses_to_channel,
            pseudo_random_generator=pseudo_random_generator,
            payer_transfer=payer_transfer,
            block_number=block_number,
        )

        events.extend(channel_events)
        events.extend(iteration.events)

    iteration = TransitionResult(mediator_state, events)
    return iteration


def handle_offchain_secretreveal(
    mediator_state: MediatorTransferState,
    mediator_state_change: ReceiveSecretReveal,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult[MediatorTransferState]:
    """Handles the secret reveal and sends SendUnlock/RevealSecret if necessary."""
    is_valid_reveal = is_valid_secret_reveal(
        state_change=mediator_state_change, transfer_secrethash=mediator_state.secrethash
    )
    is_secret_unknown = mediator_state.secret is None

    if not mediator_state.transfers_pair:
        # This will not happen during normal operation, but attackers might
        # send weird messages.
        return TransitionResult(mediator_state, [])

    # a SecretReveal should be rejected if the payer transfer
    # has expired. To check for this, we use the last
    # transfer pair.
    transfer_pair = mediator_state.transfers_pair[-1]
    payer_transfer = transfer_pair.payer_transfer
    channel_identifier = payer_transfer.balance_proof.channel_identifier
    payer_channel = channelidentifiers_to_channels.get(channel_identifier)
    if not payer_channel:
        return TransitionResult(mediator_state, [])

    has_payer_transfer_expired = channel.is_transfer_expired(
        transfer=transfer_pair.payer_transfer,
        affected_channel=payer_channel,
        block_number=block_number,
    )

    if is_secret_unknown and is_valid_reveal and not has_payer_transfer_expired:
        iteration = secret_learned(
            state=mediator_state,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
            block_hash=block_hash,
            secret=mediator_state_change.secret,
            secrethash=mediator_state_change.secrethash,
            payee_address=mediator_state_change.sender,
        )

    else:
        iteration = TransitionResult(mediator_state, [])

    return iteration


def handle_onchain_secretreveal(
    mediator_state: MediatorTransferState,
    onchain_secret_reveal: ContractReceiveSecretReveal,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[MediatorTransferState]:
    """The secret was revealed on-chain, set the state of all transfers to
    secret known.
    """
    secrethash = onchain_secret_reveal.secrethash
    is_valid_reveal = is_valid_secret_reveal(
        state_change=onchain_secret_reveal, transfer_secrethash=mediator_state.secrethash
    )

    if is_valid_reveal:

        secret = onchain_secret_reveal.secret
        # Compare against the block number at which the event was emitted.
        block_number = onchain_secret_reveal.block_number

        secret_reveal = set_onchain_secret(
            state=mediator_state,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            secret=secret,
            secrethash=secrethash,
            block_number=block_number,
        )

        balance_proof = events_for_balanceproof(
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            transfers_pair=mediator_state.transfers_pair,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
            secret=secret,
            secrethash=secrethash,
        )
        iteration = TransitionResult(mediator_state, secret_reveal + balance_proof)
    else:
        iteration = TransitionResult(mediator_state, [])

    return iteration


def handle_unlock(
    mediator_state: MediatorTransferState,
    state_change: ReceiveUnlock,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
) -> TransitionResult[MediatorTransferState]:
    """Handle a ReceiveUnlock state change."""
    events = []
    balance_proof_sender = state_change.balance_proof.sender
    channel_identifier = state_change.balance_proof.channel_identifier

    for pair in mediator_state.transfers_pair:
        if pair.payer_transfer.balance_proof.sender == balance_proof_sender:
            channel_state = channelidentifiers_to_channels.get(channel_identifier)

            if channel_state:
                recipient_metadata = get_address_metadata(
                    balance_proof_sender, mediator_state.routes
                )
                is_valid, channel_events, _ = channel.handle_unlock(
                    channel_state, state_change, recipient_metadata
                )
                events.extend(channel_events)

                if is_valid:
                    unlock = EventUnlockClaimSuccess(
                        pair.payee_transfer.payment_identifier, pair.payee_transfer.lock.secrethash
                    )
                    events.append(unlock)
                    pair.payer_state = "payer_balance_proof"

    iteration = TransitionResult(mediator_state, events)
    return iteration


def handle_lock_expired(
    mediator_state: MediatorTransferState,
    state_change: ReceiveLockExpired,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    block_number: BlockNumber,
) -> TransitionResult[MediatorTransferState]:
    events: List[Event] = []

    for transfer_pair in mediator_state.transfers_pair:
        balance_proof = transfer_pair.payer_transfer.balance_proof
        channel_state = channelidentifiers_to_channels.get(balance_proof.channel_identifier)

        if not channel_state:
            return TransitionResult(mediator_state, [])

        recipient_address = channel_state.partner_state.address
        recipient_metadata = get_address_metadata(recipient_address, mediator_state.routes)
        result = channel.handle_receive_lock_expired(
            channel_state=channel_state,
            state_change=state_change,
            block_number=block_number,
            recipient_metadata=recipient_metadata,
        )
        assert result.new_state and isinstance(result.new_state, NettingChannelState), (
            "Handling a receive_lock_expire should never delete the channel task",
        )
        events.extend(result.events)
        if not channel.get_lock(result.new_state.partner_state, mediator_state.secrethash):
            transfer_pair.payer_state = "payer_expired"

    if mediator_state.waiting_transfer:
        waiting_channel = channelidentifiers_to_channels.get(
            mediator_state.waiting_transfer.transfer.balance_proof.channel_identifier
        )
        if waiting_channel:
            recipient_address = waiting_channel.partner_state.address
            recipient_metadata = get_address_metadata(recipient_address, mediator_state.routes)
            result = channel.handle_receive_lock_expired(
                channel_state=waiting_channel,
                state_change=state_change,
                block_number=block_number,
                recipient_metadata=recipient_metadata,
            )
            events.extend(result.events)

    return TransitionResult(mediator_state, events)


def state_transition(
    mediator_state: Optional[MediatorTransferState],
    state_change: StateChange,
    channelidentifiers_to_channels: Dict[ChannelID, NettingChannelState],
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult[Optional[MediatorTransferState]]:
    """State machine for a node mediating a transfer."""
    # pylint: disable=too-many-branches
    # Notes:
    # - A user cannot cancel a mediated transfer after it was initiated, she
    #   may only reject to mediate before hand. This is because the mediator
    #   doesn't control the secret reveal and needs to wait for the lock
    #   expiration before safely discarding the transfer.

    iteration = TransitionResult(mediator_state, [])

    if type(state_change) == ActionInitMediator:
        assert isinstance(state_change, ActionInitMediator), MYPY_ANNOTATION
        if mediator_state is None:
            iteration = handle_init(
                state_change=state_change,
                channelidentifiers_to_channels=channelidentifiers_to_channels,
                addresses_to_channel=addresses_to_channel,
                pseudo_random_generator=pseudo_random_generator,
                block_number=block_number,
            )

    elif type(state_change) == Block:
        assert isinstance(state_change, Block), MYPY_ANNOTATION
        assert mediator_state, "Block should be accompanied by a valid mediator state"
        iteration = handle_block(
            mediator_state=mediator_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            addresses_to_channel=addresses_to_channel,
            pseudo_random_generator=pseudo_random_generator,
        )

    elif type(state_change) == ReceiveTransferRefund:
        assert isinstance(state_change, ReceiveTransferRefund), MYPY_ANNOTATION
        msg = "ReceiveTransferRefund should be accompanied by a valid mediator state"
        assert mediator_state, msg
        iteration = handle_refundtransfer(
            mediator_state=mediator_state,
            mediator_state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            addresses_to_channel=addresses_to_channel,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )

    elif type(state_change) == ReceiveSecretReveal:
        assert isinstance(state_change, ReceiveSecretReveal), MYPY_ANNOTATION
        msg = "ReceiveSecretReveal should be accompanied by a valid mediator state"
        assert mediator_state, msg
        iteration = handle_offchain_secretreveal(
            mediator_state=mediator_state,
            mediator_state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
            block_hash=block_hash,
        )

    elif type(state_change) == ContractReceiveSecretReveal:
        assert isinstance(state_change, ContractReceiveSecretReveal), MYPY_ANNOTATION
        msg = "ContractReceiveSecretReveal should be accompanied by a valid mediator state"
        assert mediator_state, msg
        iteration = handle_onchain_secretreveal(
            mediator_state=mediator_state,
            onchain_secret_reveal=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )

    elif type(state_change) == ReceiveUnlock:
        assert isinstance(state_change, ReceiveUnlock), MYPY_ANNOTATION
        assert mediator_state, "ReceiveUnlock should be accompanied by a valid mediator state"
        iteration = handle_unlock(
            mediator_state=mediator_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
        )

    elif type(state_change) == ReceiveLockExpired:
        assert isinstance(state_change, ReceiveLockExpired), MYPY_ANNOTATION
        assert mediator_state, "ReceiveLockExpired should be accompanied by a valid mediator state"
        iteration = handle_lock_expired(
            mediator_state=mediator_state,
            state_change=state_change,
            channelidentifiers_to_channels=channelidentifiers_to_channels,
            block_number=block_number,
        )

    # this is the place for paranoia
    if iteration.new_state is not None:
        typecheck(iteration.new_state, MediatorTransferState)
        sanity_check(iteration.new_state, channelidentifiers_to_channels)

    return clear_if_finalized(iteration, channelidentifiers_to_channels)
