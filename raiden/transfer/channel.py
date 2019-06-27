# pylint: disable=too-many-lines
import heapq
import random

from eth_utils import encode_hex, keccak, to_hex

from raiden.constants import LOCKSROOT_OF_NO_LOCKS, MAXIMUM_PENDING_TRANSFERS, UINT256_MAX
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelWithdraw,
    EventInvalidActionWithdraw,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
    EventInvalidReceivedWithdraw,
    EventInvalidReceivedWithdrawExpired,
    EventInvalidReceivedWithdrawRequest,
    SendProcessed,
    SendWithdrawConfirmation,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.transfer.identifiers import CANONICAL_IDENTIFIER_GLOBAL_QUEUE, CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import (
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    refund_from_sendmediated,
)
from raiden.transfer.mediated_transfer.mediation_fee import calculate_imbalance_fees
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    LockedTransferUnsignedState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveLockExpired,
    ReceiveTransferRefund,
)
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    HashTimeLockState,
    NettingChannelEndState,
    NettingChannelState,
    PendingLocksState,
    RouteState,
    TransactionChannelNewBalance,
    TransactionExecutionStatus,
    TransactionOrder,
    UnlockPartialProofState,
    WithdrawState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import (
    ActionChannelClose,
    ActionChannelUpdateFee,
    ActionChannelWithdraw,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveChannelWithdraw,
    ContractReceiveUpdateTransfer,
    ReceiveUnlock,
    ReceiveWithdrawConfirmation,
    ReceiveWithdrawExpired,
    ReceiveWithdrawRequest,
)
from raiden.transfer.utils import hash_balance_data
from raiden.utils.packing import pack_balance_proof, pack_withdraw
from raiden.utils.signer import recover
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    Balance,
    BlockExpiration,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChainID,
    ChannelID,
    EncodedData,
    InitiatorAddress,
    List,
    Locksroot,
    LockType,
    MessageID,
    NamedTuple,
    Nonce,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    Signature,
    SuccessOrError,
    TargetAddress,
    TokenAmount,
    TokenNetworkAddress,
    Tuple,
    Union,
    WithdrawAmount,
)

# This should be changed to `Union[str, PendingLocksState]`
PendingLocksStateOrError = Tuple[bool, Optional[str], Optional[PendingLocksState]]
EventsOrError = Tuple[bool, List[Event], Optional[str]]
BalanceProofData = Tuple[Locksroot, Nonce, TokenAmount, TokenAmount]
SendUnlockAndPendingLocksState = Tuple[SendBalanceProof, PendingLocksState]


class UnlockGain(NamedTuple):
    from_our_locks: TokenAmount
    from_partner_locks: TokenAmount


def get_safe_initial_expiration(
    block_number: BlockNumber, reveal_timeout: BlockTimeout
) -> BlockExpiration:
    """ Returns the upper bound block expiration number used by the initiator of
    a transfer or a withdraw. """
    return BlockExpiration(block_number + reveal_timeout * 2)


def get_sender_expiration_threshold(expiration: BlockExpiration) -> BlockNumber:
    """ Returns the block number at which the sender can send:
    - SendLockExpired
    - SendWithdrawExpired

    The expiry messages will be rejected if the expiration block
    has not been confirmed. Additionally the sender can account for possible
    delays in the receiver, so a few additional blocks are used to avoid hanging the channel.
    """
    return BlockExpiration(expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2)


def get_receiver_expiration_threshold(expiration: BlockExpiration) -> BlockNumber:
    """ Returns the block number at which the receiver can accept:
    - ReceiveLockExpired
    - ReceiveWithdrawExpired

    The receiver must wait for the block at which the lock expires to be confirmed.
    This is necessary to handle reorgs which could hide a secret registration.
    """
    return BlockExpiration(expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS)


def is_channel_usable(
    candidate_channel_state: NettingChannelState,
    transfer_amount: PaymentWithFeeAmount,
    lock_timeout: BlockTimeout = None,
) -> bool:
    pending_transfers = get_number_of_pending_transfers(candidate_channel_state.our_state)
    distributable = get_distributable(
        candidate_channel_state.our_state, candidate_channel_state.partner_state
    )

    channel_usable = (
        get_status(candidate_channel_state) == CHANNEL_STATE_OPENED
        and pending_transfers < MAXIMUM_PENDING_TRANSFERS
        and transfer_amount <= distributable
        and is_valid_amount(candidate_channel_state.our_state, transfer_amount)
    )

    lock_timeout_valid = True
    if lock_timeout is not None:
        lock_timeout_valid = (
            lock_timeout > 0
            and candidate_channel_state.settle_timeout >= lock_timeout
            and candidate_channel_state.reveal_timeout < lock_timeout
        )

    return channel_usable and lock_timeout_valid


def is_lock_pending(end_state: NettingChannelEndState, secrethash: SecretHash) -> bool:
    """True if the `secrethash` corresponds to a lock that is pending to be claimed
    and didn't expire.
    """
    return (
        secrethash in end_state.secrethashes_to_lockedlocks
        or secrethash in end_state.secrethashes_to_unlockedlocks
        or secrethash in end_state.secrethashes_to_onchain_unlockedlocks
    )


def is_deposit_confirmed(channel_state: NettingChannelState, block_number: BlockNumber) -> bool:
    """True if the block which mined the deposit transaction has been
    confirmed.
    """
    if not channel_state.deposit_transaction_queue:
        return False

    return is_transaction_confirmed(
        channel_state.deposit_transaction_queue[0].block_number, block_number
    )


def is_lock_locked(end_state: NettingChannelEndState, secrethash: SecretHash) -> bool:
    """True if the `secrethash` is for a lock with an unknown secret."""
    return secrethash in end_state.secrethashes_to_lockedlocks


def is_lock_expired(
    end_state: NettingChannelEndState,
    lock: LockType,
    block_number: BlockNumber,
    lock_expiration_threshold: BlockNumber,
) -> SuccessOrError:
    """ Determine whether a lock has expired.

    The lock has expired if both:

        - The secret was not registered on-chain in time.
        - The current block exceeds lock's expiration + confirmation blocks.
    """

    secret_registered_on_chain = lock.secrethash in end_state.secrethashes_to_onchain_unlockedlocks
    if secret_registered_on_chain:
        return (False, "lock has been unlocked on-chain")

    if block_number < lock_expiration_threshold:
        msg = (
            f"current block number ({block_number}) is not larger than "
            f"lock.expiration + confirmation blocks ({lock_expiration_threshold})"
        )
        return (False, msg)

    return (True, None)


def is_transfer_expired(
    transfer: LockedTransferSignedState,
    affected_channel: NettingChannelState,
    block_number: BlockNumber,
) -> bool:
    lock_expiration_threshold = get_sender_expiration_threshold(transfer.lock.expiration)
    has_lock_expired, _ = is_lock_expired(
        end_state=affected_channel.our_state,
        lock=transfer.lock,
        block_number=block_number,
        lock_expiration_threshold=lock_expiration_threshold,
    )
    return has_lock_expired


def is_secret_known(end_state: NettingChannelEndState, secrethash: SecretHash) -> bool:
    """True if the `secrethash` is for a lock with a known secret."""
    return (
        secrethash in end_state.secrethashes_to_unlockedlocks
        or secrethash in end_state.secrethashes_to_onchain_unlockedlocks
    )


def is_secret_known_offchain(end_state: NettingChannelEndState, secrethash: SecretHash) -> bool:
    """True if the `secrethash` is for a lock with a known secret."""
    return secrethash in end_state.secrethashes_to_unlockedlocks


def is_secret_known_onchain(end_state: NettingChannelEndState, secrethash: SecretHash) -> bool:
    """True if the `secrethash` is for a lock with a known secret."""
    return secrethash in end_state.secrethashes_to_onchain_unlockedlocks


def get_secret(end_state: NettingChannelEndState, secrethash: SecretHash) -> Optional[Secret]:
    """Returns `secret` if the `secrethash` is for a lock with a known secret."""
    partial_unlock_proof = end_state.secrethashes_to_unlockedlocks.get(secrethash)

    if partial_unlock_proof is None:
        partial_unlock_proof = end_state.secrethashes_to_onchain_unlockedlocks.get(secrethash)

    if partial_unlock_proof is not None:
        return partial_unlock_proof.secret

    return None


def is_transaction_confirmed(
    transaction_block_number: BlockNumber, blockchain_block_number: BlockNumber
) -> bool:
    confirmation_block = transaction_block_number + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    return blockchain_block_number > confirmation_block


def is_balance_proof_safe_for_onchain_operations(balance_proof: BalanceProofSignedState,) -> bool:
    """ Check if the balance proof would overflow onchain. """
    total_amount = balance_proof.transferred_amount + balance_proof.locked_amount
    return total_amount <= UINT256_MAX


def is_valid_amount(
    end_state: NettingChannelEndState,
    amount: Union[TokenAmount, PaymentAmount, PaymentWithFeeAmount],
) -> bool:
    (_, _, current_transferred_amount, current_locked_amount) = get_current_balanceproof(end_state)

    transferred_amount_after_unlock = current_transferred_amount + current_locked_amount + amount

    return transferred_amount_after_unlock <= UINT256_MAX


def is_valid_signature(
    data: bytes, signature: Signature, sender_address: Address
) -> SuccessOrError:
    try:
        signer_address = recover(data=data, signature=signature)
        # InvalidSignature is raised by raiden.utils.signer.recover if signature
        # is not bytes or has the incorrect length.
        # ValueError is raised if the PublicKey instantiation failed.
        # Exception is raised if the public key recovery failed.
    except Exception:  # pylint: disable=broad-except
        msg = "Signature invalid, could not be recovered."
        return (False, msg)

    is_correct_sender = sender_address == signer_address
    if is_correct_sender:
        return (True, None)

    msg = "Signature was valid but the expected address does not match."
    return (False, msg)


def is_valid_balanceproof_signature(
    balance_proof: BalanceProofSignedState, sender_address: Address
) -> SuccessOrError:
    balance_hash = hash_balance_data(
        balance_proof.transferred_amount, balance_proof.locked_amount, balance_proof.locksroot
    )

    # The balance proof must be tied to a single channel instance, through the
    # chain_id, token_network_address, and channel_identifier, otherwise the
    # on-chain contract would be susceptible to replay attacks across channels.
    #
    # The balance proof must also authenticate the offchain balance (blinded in
    # the balance_hash field), and authenticate the rest of message data
    # (blinded in additional_hash).
    data_that_was_signed = pack_balance_proof(
        nonce=balance_proof.nonce,
        balance_hash=balance_hash,
        additional_hash=balance_proof.message_hash,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=balance_proof.chain_id,
            token_network_address=balance_proof.token_network_address,
            channel_identifier=balance_proof.channel_identifier,
        ),
    )

    return is_valid_signature(
        data=data_that_was_signed, signature=balance_proof.signature, sender_address=sender_address
    )


def is_balance_proof_usable_onchain(
    received_balance_proof: BalanceProofSignedState,
    channel_state: NettingChannelState,
    sender_state: NettingChannelEndState,
) -> SuccessOrError:
    """ Checks the balance proof can be used on-chain.

    For a balance proof to be valid it must be newer than the previous one,
    i.e. the nonce must increase, the signature must tie the balance proof to
    the correct channel, and the values must not result in an under/overflow
    onchain.

    Important: This predicate does not validate all the message fields. The
    fields locksroot, transferred_amount, and locked_amount **MUST** be
    validated elsewhere based on the message type.
    """
    expected_nonce = get_next_nonce(sender_state)

    balanceproof_signature_valid, signature_msg = is_valid_balanceproof_signature(
        received_balance_proof, sender_state.address
    )

    result: SuccessOrError

    # TODO: Accept unlock messages if the node has not yet sent a transaction
    # with the balance proof to the blockchain, this will save one call to
    # unlock on-chain for the non-closing party.
    if get_status(channel_state) != CHANNEL_STATE_OPENED:
        # The channel must be opened, otherwise if receiver is the closer, the
        # balance proof cannot be used onchain.
        msg = f"The channel is already closed."
        result = (False, msg)

    elif received_balance_proof.channel_identifier != channel_state.identifier:
        # Informational message, the channel_identifier **validated by the
        # signature** must match for the balance_proof to be valid.
        msg = (
            f"channel_identifier does not match. "
            f"expected: {channel_state.identifier} "
            f"got: {received_balance_proof.channel_identifier}."
        )
        result = (False, msg)

    elif received_balance_proof.token_network_address != channel_state.token_network_address:
        # Informational message, the token_network_address **validated by
        # the signature** must match for the balance_proof to be valid.
        msg = (
            f"token_network_address does not match. "
            f"expected: {channel_state.token_network_address} "
            f"got: {received_balance_proof.token_network_address}."
        )
        result = (False, msg)

    elif received_balance_proof.chain_id != channel_state.chain_id:
        # Informational message, the chain_id **validated by the signature**
        # must match for the balance_proof to be valid.
        msg = (
            f"chain_id does not match channel's "
            f"chain_id. expected: {channel_state.chain_id} "
            f"got: {received_balance_proof.chain_id}."
        )
        result = (False, msg)

    elif not is_balance_proof_safe_for_onchain_operations(received_balance_proof):
        transferred_amount_after_unlock = (
            received_balance_proof.transferred_amount + received_balance_proof.locked_amount
        )
        msg = (
            f"Balance proof total transferred amount would overflow onchain. "
            f"max: {UINT256_MAX} result would be: {transferred_amount_after_unlock}"
        )

        result = (False, msg)

    elif received_balance_proof.nonce != expected_nonce:
        # The nonces must increase sequentially, otherwise there is a
        # synchronization problem.
        msg = (
            f"Nonce did not change sequentially, expected: {expected_nonce} "
            f"got: {received_balance_proof.nonce}."
        )

        result = (False, msg)

    elif not balanceproof_signature_valid:
        # The signature must be valid, otherwise the balance proof cannot be
        # used onchain.
        result = (False, signature_msg)

    else:
        result = (True, None)

    return result


def is_valid_lockedtransfer(
    transfer_state: LockedTransferSignedState,
    channel_state: NettingChannelState,
    sender_state: NettingChannelEndState,
    receiver_state: NettingChannelEndState,
) -> PendingLocksStateOrError:
    return valid_lockedtransfer_check(
        channel_state=channel_state,
        sender_state=sender_state,
        receiver_state=receiver_state,
        message_name="LockedTransfer",
        received_balance_proof=transfer_state.balance_proof,
        lock=transfer_state.lock,
    )


def is_valid_lock_expired(
    state_change: ReceiveLockExpired,
    channel_state: NettingChannelState,
    sender_state: NettingChannelEndState,
    receiver_state: NettingChannelEndState,
    block_number: BlockNumber,
) -> PendingLocksStateOrError:
    secrethash = state_change.secrethash
    received_balance_proof = state_change.balance_proof

    # If the lock was not found in locked locks, this means that we've received
    # the secret for the locked transfer but we haven't unlocked it yet. Lock
    # expiry in this case could still happen which means that we have to make
    # sure that we check for "unclaimed" locks in our check.
    lock = channel_state.partner_state.secrethashes_to_lockedlocks.get(secrethash)
    if not lock:
        partial_lock = channel_state.partner_state.secrethashes_to_unlockedlocks.get(secrethash)
        if partial_lock:
            lock = partial_lock.lock

    secret_registered_on_chain = (
        secrethash in channel_state.partner_state.secrethashes_to_onchain_unlockedlocks
    )

    current_balance_proof = get_current_balanceproof(sender_state)
    _, _, current_transferred_amount, current_locked_amount = current_balance_proof

    is_balance_proof_usable, invalid_balance_proof_msg = is_balance_proof_usable_onchain(
        received_balance_proof=received_balance_proof,
        channel_state=channel_state,
        sender_state=sender_state,
    )

    if lock:
        pending_locks = compute_locks_without(
            sender_state.pending_locks, EncodedData(bytes(lock.encoded))
        )
        expected_locked_amount = current_locked_amount - lock.amount

    result: PendingLocksStateOrError = (False, None, None)

    if secret_registered_on_chain:
        msg = "Invalid LockExpired mesage. Lock was unlocked on-chain."
        result = (False, msg, None)

    elif lock is None:
        msg = (
            f"Invalid LockExpired message. "
            f"Lock with secrethash {to_hex(secrethash)} is not known."
        )
        result = (False, msg, None)

    elif not is_balance_proof_usable:
        msg = f"Invalid LockExpired message. {invalid_balance_proof_msg}"
        result = (False, msg, None)

    elif pending_locks is None:
        msg = "Invalid LockExpired message. Same lock handled twice."
        result = (False, msg, None)

    else:
        locksroot_without_lock = compute_locksroot(pending_locks)
        has_expired, lock_expired_message = is_lock_expired(
            end_state=receiver_state,
            lock=lock,
            block_number=block_number,
            lock_expiration_threshold=get_receiver_expiration_threshold(lock.expiration),
        )

        if not has_expired:
            msg = f"Invalid LockExpired message. {lock_expired_message}"
            result = (False, msg, None)

        elif received_balance_proof.locksroot != locksroot_without_lock:
            # The locksroot must be updated, and the expired lock must be *removed*
            msg = (
                "Invalid LockExpired message. "
                "Balance proof's locksroot didn't match, expected: {} got: {}."
            ).format(
                encode_hex(locksroot_without_lock), encode_hex(received_balance_proof.locksroot)
            )

            result = (False, msg, None)

        elif received_balance_proof.transferred_amount != current_transferred_amount:
            # Given an expired lock, transferred amount should stay the same
            msg = (
                "Invalid LockExpired message. "
                "Balance proof's transferred_amount changed, expected: {} got: {}."
            ).format(current_transferred_amount, received_balance_proof.transferred_amount)

            result = (False, msg, None)

        elif received_balance_proof.locked_amount != expected_locked_amount:
            # locked amount should be the same found inside the balance proof
            msg = (
                "Invalid LockExpired message. "
                "Balance proof's locked_amount is invalid, expected: {} got: {}."
            ).format(expected_locked_amount, received_balance_proof.locked_amount)

            result = (False, msg, None)

        else:
            result = (True, None, pending_locks)

    return result


def valid_lockedtransfer_check(
    channel_state: NettingChannelState,
    sender_state: NettingChannelEndState,
    receiver_state: NettingChannelEndState,
    message_name: str,
    received_balance_proof: BalanceProofSignedState,
    lock: HashTimeLockState,
) -> PendingLocksStateOrError:

    current_balance_proof = get_current_balanceproof(sender_state)
    pending_locks = compute_locks_with(sender_state.pending_locks, lock)

    _, _, current_transferred_amount, current_locked_amount = current_balance_proof
    distributable = get_distributable(sender_state, receiver_state)
    expected_locked_amount = current_locked_amount + lock.amount

    is_balance_proof_usable, invalid_balance_proof_msg = is_balance_proof_usable_onchain(
        received_balance_proof=received_balance_proof,
        channel_state=channel_state,
        sender_state=sender_state,
    )

    result: PendingLocksStateOrError = (False, None, None)

    if not is_balance_proof_usable:
        msg = f"Invalid {message_name} message. {invalid_balance_proof_msg}"
        result = (False, msg, None)

    elif pending_locks is None:
        msg = f"Invalid {message_name} message. Same lock handled twice."
        result = (False, msg, None)

    elif len(pending_locks.locks) > MAXIMUM_PENDING_TRANSFERS:
        msg = (
            f"Invalid {message_name} message. Adding the transfer would exceed the allowed "
            f"limit of {MAXIMUM_PENDING_TRANSFERS} pending transfers per channel."
        )
        result = (False, msg, None)

    else:
        locksroot_with_lock = compute_locksroot(pending_locks)

        if received_balance_proof.locksroot != locksroot_with_lock:
            # The locksroot must be updated to include the new lock
            msg = (
                "Invalid {} message. "
                "Balance proof's locksroot didn't match, expected: {} got: {}."
            ).format(
                message_name,
                encode_hex(locksroot_with_lock),
                encode_hex(received_balance_proof.locksroot),
            )

            result = (False, msg, None)

        elif received_balance_proof.transferred_amount != current_transferred_amount:
            # Mediated transfers must not change transferred_amount
            msg = (
                "Invalid {} message. "
                "Balance proof's transferred_amount changed, expected: {} got: {}."
            ).format(
                message_name, current_transferred_amount, received_balance_proof.transferred_amount
            )

            result = (False, msg, None)

        elif received_balance_proof.locked_amount != expected_locked_amount:
            # Mediated transfers must increase the locked_amount by lock.amount
            msg = (
                "Invalid {} message. "
                "Balance proof's locked_amount is invalid, expected: {} got: {}."
            ).format(message_name, expected_locked_amount, received_balance_proof.locked_amount)

            result = (False, msg, None)

        # the locked amount is limited to the current available balance, otherwise
        # the sender is attempting to game the protocol and do a double spend
        elif lock.amount > distributable:
            msg = (
                "Invalid {} message. "
                "Lock amount larger than the available distributable, "
                "lock amount: {} maximum distributable: {}"
            ).format(message_name, lock.amount, distributable)

            result = (False, msg, None)

        else:
            result = (True, None, pending_locks)

    return result


def refund_transfer_matches_transfer(
    refund_transfer: LockedTransferSignedState, transfer: LockedTransferUnsignedState
) -> bool:
    refund_transfer_sender = refund_transfer.balance_proof.sender
    # Ignore a refund from the target
    if refund_transfer_sender == transfer.target:
        return False

    return (
        transfer.payment_identifier == refund_transfer.payment_identifier
        and transfer.lock.amount == refund_transfer.lock.amount
        and transfer.lock.secrethash == refund_transfer.lock.secrethash
        and transfer.target == refund_transfer.target
        and transfer.lock.expiration == refund_transfer.lock.expiration
        and
        # The refund transfer is not tied to the other direction of the same
        # channel, it may reach this node through a different route depending
        # on the path finding strategy
        # original_receiver == refund_transfer_sender and
        transfer.token == refund_transfer.token
    )


def is_valid_refund(
    refund: ReceiveTransferRefund,
    channel_state: NettingChannelState,
    sender_state: NettingChannelEndState,
    receiver_state: NettingChannelEndState,
    received_transfer: LockedTransferUnsignedState,
) -> PendingLocksStateOrError:
    is_valid_locked_transfer, msg, pending_locks = valid_lockedtransfer_check(
        channel_state,
        sender_state,
        receiver_state,
        "RefundTransfer",
        refund.transfer.balance_proof,
        refund.transfer.lock,
    )

    if not is_valid_locked_transfer:
        return False, msg, None

    if not refund_transfer_matches_transfer(refund.transfer, received_transfer):
        return False, "Refund transfer did not match the received transfer", None

    return True, "", pending_locks


def is_valid_unlock(
    unlock: ReceiveUnlock, channel_state: NettingChannelState, sender_state: NettingChannelEndState
) -> PendingLocksStateOrError:
    received_balance_proof = unlock.balance_proof
    current_balance_proof = get_current_balanceproof(sender_state)

    lock = get_lock(sender_state, unlock.secrethash)

    if lock is None:
        msg = "Invalid Unlock message. There is no corresponding lock for {}".format(
            encode_hex(unlock.secrethash)
        )
        return (False, msg, None)

    pending_locks = compute_locks_without(
        sender_state.pending_locks, EncodedData(bytes(lock.encoded))
    )

    if pending_locks is None:
        msg = f"Invalid unlock message. The lock is unknown {encode_hex(lock.encoded)}"
        return (False, msg, None)

    locksroot_without_lock = compute_locksroot(pending_locks)

    _, _, current_transferred_amount, current_locked_amount = current_balance_proof

    expected_transferred_amount = current_transferred_amount + TokenAmount(lock.amount)
    expected_locked_amount = current_locked_amount - lock.amount

    is_balance_proof_usable, invalid_balance_proof_msg = is_balance_proof_usable_onchain(
        received_balance_proof=received_balance_proof,
        channel_state=channel_state,
        sender_state=sender_state,
    )

    result: PendingLocksStateOrError = (False, None, None)

    if not is_balance_proof_usable:
        msg = f"Invalid Unlock message. {invalid_balance_proof_msg}"
        result = (False, msg, None)

    elif received_balance_proof.locksroot != locksroot_without_lock:
        # Unlock messages remove a known lock, the new locksroot must have only
        # that lock removed, otherwise the sender may be trying to remove
        # additional locks.
        msg = (
            "Invalid Unlock message. "
            "Balance proof's locksroot didn't match, expected: {} got: {}."
        ).format(encode_hex(locksroot_without_lock), encode_hex(received_balance_proof.locksroot))

        result = (False, msg, None)

    elif received_balance_proof.transferred_amount != expected_transferred_amount:
        # Unlock messages must increase the transferred_amount by lock amount,
        # otherwise the sender is trying to play the protocol and steal token.
        msg = (
            "Invalid Unlock message. "
            "Balance proof's wrong transferred_amount, expected: {} got: {}."
        ).format(expected_transferred_amount, received_balance_proof.transferred_amount)

        result = (False, msg, None)

    elif received_balance_proof.locked_amount != expected_locked_amount:
        # Unlock messages must increase the transferred_amount by lock amount,
        # otherwise the sender is trying to play the protocol and steal token.
        msg = (
            "Invalid Unlock message. " "Balance proof's wrong locked_amount, expected: {} got: {}."
        ).format(expected_locked_amount, received_balance_proof.locked_amount)

        result = (False, msg, None)

    else:
        result = (True, None, pending_locks)

    return result


def is_valid_action_withdraw(
    channel_state: NettingChannelState, withdraw: ActionChannelWithdraw
) -> SuccessOrError:
    result: SuccessOrError

    balance = get_balance(sender=channel_state.our_state, receiver=channel_state.partner_state)

    # Does our new total_withdraw with the partner's total_withdraw cause an overflow?
    total_channel_withdraw = withdraw.total_withdraw + channel_state.partner_state.total_withdraw
    withdraw_overflow = total_channel_withdraw >= UINT256_MAX

    withdraw_amount = withdraw.total_withdraw - channel_state.our_state.total_withdraw
    if withdraw_amount <= 0:
        msg = f"Total withdraw {withdraw.total_withdraw} did not increase"
        result = (False, msg)
    elif balance < withdraw_amount:
        msg = "Insufficient balance: {}. Requested {} for withdraw".format(
            balance, withdraw_amount
        )
        result = (False, msg)
    elif withdraw_overflow:
        msg = f"The new total_withdraw {withdraw.total_withdraw} will cause an overflow"
        result = (False, msg)
    else:
        result = (True, None)

    return result


def is_valid_withdraw_request(
    channel_state: NettingChannelState, withdraw_request: ReceiveWithdrawRequest
) -> SuccessOrError:
    result: SuccessOrError

    expected_nonce = get_next_nonce(channel_state.partner_state)
    balance = get_balance(sender=channel_state.partner_state, receiver=channel_state.our_state)

    packed = pack_withdraw(
        canonical_identifier=withdraw_request.canonical_identifier,
        participant=channel_state.partner_state.address,
        total_withdraw=withdraw_request.total_withdraw,
    )

    valid_signature, signature_msg = is_valid_signature(
        data=packed,
        signature=withdraw_request.signature,
        sender_address=channel_state.partner_state.address,
    )

    withdraw_amount = withdraw_request.total_withdraw - channel_state.partner_state.total_withdraw

    # Does the new partner total_withdraw with our total_withdraw cause an overflow?
    total_channel_withdraw = (
        withdraw_request.total_withdraw + channel_state.our_state.total_withdraw
    )
    withdraw_overflow = total_channel_withdraw >= UINT256_MAX

    if channel_state.canonical_identifier != withdraw_request.canonical_identifier:
        msg = f"Invalid canonical identifier provided in withdraw request"
        result = (False, msg)
    elif withdraw_amount <= 0:
        msg = f"Total withdraw {withdraw_request.total_withdraw} did not increase"
        result = (False, msg)
    elif balance < withdraw_amount:
        msg = "Insufficient balance: {}. Requested {} for withdraw".format(
            balance, withdraw_amount
        )
        result = (False, msg)
    elif not valid_signature:
        result = (False, signature_msg)
    elif withdraw_request.nonce != expected_nonce:
        msg = (
            f"Nonce did not change sequentially, expected: {expected_nonce} "
            f"got: {withdraw_request.nonce}."
        )

        result = (False, msg)
    elif withdraw_overflow:
        msg = f"The new total_withdraw {withdraw_request.total_withdraw} will cause an overflow"
        result = (False, msg)
    else:
        result = (True, None)

    return result


def is_valid_withdraw_confirmation(
    channel_state: NettingChannelState, withdraw: ReceiveWithdrawConfirmation
) -> SuccessOrError:

    result: SuccessOrError

    withdraw_exists = withdraw.total_withdraw in [
        withdraw_state.total_withdraw for withdraw_state in channel_state.our_state.withdraws
    ]

    expected_nonce = get_next_nonce(channel_state.partner_state)

    packed = pack_withdraw(
        canonical_identifier=withdraw.canonical_identifier,
        participant=channel_state.our_state.address,
        total_withdraw=withdraw.total_withdraw,
    )

    valid_signature, signature_msg = is_valid_signature(
        data=packed,
        signature=withdraw.signature,
        sender_address=channel_state.partner_state.address,
    )

    # Does our new total_withdraw with the partner's total_withdraw cause an overflow?
    total_channel_withdraw = withdraw.total_withdraw + channel_state.partner_state.total_withdraw
    withdraw_overflow = total_channel_withdraw >= UINT256_MAX

    if channel_state.canonical_identifier != withdraw.canonical_identifier:
        msg = f"Invalid canonical identifier provided in withdraw request"

    if not withdraw_exists:
        msg = "Received withdraw confirmation {} was not found in withdraw states".format(
            withdraw.total_withdraw
        )
        result = (False, msg)
    elif withdraw.total_withdraw != channel_state.our_state.total_withdraw:
        msg = "Total withdraw confirmation {} does not match our total withdraw {}".format(
            withdraw.total_withdraw, channel_state.our_state.total_withdraw
        )
        result = (False, msg)

    elif not valid_signature:
        result = (False, signature_msg)
    elif withdraw.nonce != expected_nonce:
        msg = (
            f"Nonce did not change sequentially, expected: {expected_nonce} "
            f"got: {withdraw.nonce}."
        )

        result = (False, msg)
    elif withdraw_overflow:
        msg = f"The new total_withdraw {withdraw.total_withdraw} will cause an overflow"
        result = (False, msg)
    else:
        result = (True, None)

    return result


def is_valid_withdraw_expired(
    channel_state: NettingChannelState,
    state_change: ReceiveWithdrawExpired,
    withdraw_state: WithdrawState,
    block_number: BlockNumber,
) -> SuccessOrError:
    result: SuccessOrError

    expected_nonce = get_next_nonce(channel_state.partner_state)

    packed = pack_withdraw(
        canonical_identifier=state_change.canonical_identifier,
        participant=channel_state.partner_state.address,
        total_withdraw=state_change.total_withdraw,
    )

    valid_signature, signature_msg = is_valid_signature(
        data=packed,
        signature=state_change.signature,
        sender_address=channel_state.partner_state.address,
    )

    withdraw_expired = is_withdraw_expired(
        block_number=block_number,
        expiration_threshold=get_receiver_expiration_threshold(
            expiration=withdraw_state.expiration
        ),
    )

    if not withdraw_expired:
        msg = f"Invalid WithdrawExpired of {state_change.total_withdraw}"
        result = (False, msg)
    elif not valid_signature:
        result = (False, signature_msg)
    elif state_change.nonce != expected_nonce:
        msg = (
            f"Nonce did not change sequentially, expected: {expected_nonce} "
            f"got: {state_change.nonce}."
        )

        result = (False, msg)
    else:
        result = (True, None)

    return result


def get_amount_unclaimed_onchain(end_state: NettingChannelEndState) -> TokenAmount:
    return TokenAmount(
        sum(
            unlock.lock.amount
            for unlock in end_state.secrethashes_to_onchain_unlockedlocks.values()
        )
    )


def get_amount_locked(end_state: NettingChannelEndState) -> TokenAmount:
    total_pending = sum(lock.amount for lock in end_state.secrethashes_to_lockedlocks.values())

    total_unclaimed = sum(
        unlock.lock.amount for unlock in end_state.secrethashes_to_unlockedlocks.values()
    )

    total_unclaimed_onchain = get_amount_unclaimed_onchain(end_state)

    result = total_pending + total_unclaimed + total_unclaimed_onchain
    return TokenAmount(result)


def get_batch_unlock_gain(channel_state: NettingChannelState,) -> UnlockGain:
    """Collect amounts for unlocked/unclaimed locks and onchain unlocked locks.
    Note: this function does not check expiry, so the values make only sense during settlement.

    Returns:
        gain_from_partner_locks: locks amount received and unlocked on-chain
        gain_from_our_locks: locks amount which are unlocked or unclaimed
    """
    sum_from_partner_locks = sum(
        unlock.lock.amount
        for unlock in channel_state.partner_state.secrethashes_to_onchain_unlockedlocks.values()
    )
    gain_from_partner_locks = TokenAmount(sum_from_partner_locks)

    """
    The current participant will gain from unlocking its own locks when:
    - The partner never managed to provide the secret to unlock the locked amount.
    - The partner provided the secret to claim the locked amount but the current
      participant node never sent out the unlocked balance proof and the partner
      did not unlock the lock on-chain.
    """
    our_locked_locks_amount = sum(
        lock.amount for lock in channel_state.our_state.secrethashes_to_lockedlocks.values()
    )
    our_unclaimed_locks_amount = sum(
        lock.amount for lock in channel_state.our_state.secrethashes_to_unlockedlocks.values()
    )
    gain_from_our_locks = TokenAmount(our_locked_locks_amount + our_unclaimed_locks_amount)
    return UnlockGain(
        from_partner_locks=gain_from_partner_locks, from_our_locks=gain_from_our_locks
    )


def get_capacity(channel_state: NettingChannelState) -> TokenAmount:
    """ Calculates the capacity of the given channel

    For the definition of capacity see
    https://raiden-network.readthedocs.io/en/stable/glossary.html#term-channel-capacity
    """
    return TokenAmount(
        channel_state.our_total_deposit
        - channel_state.our_total_withdraw
        + channel_state.partner_total_deposit
        - channel_state.partner_total_withdraw
    )


def get_balance(sender: NettingChannelEndState, receiver: NettingChannelEndState) -> Balance:
    """ Calculates the balance for a participant in a channel.

    For the definition of balance see
    https://raiden-network.readthedocs.io/en/stable/glossary.html#term-balance
    """
    sender_transferred_amount = 0
    receiver_transferred_amount = 0

    if sender.balance_proof:
        sender_transferred_amount = sender.balance_proof.transferred_amount

    if receiver.balance_proof:
        receiver_transferred_amount = receiver.balance_proof.transferred_amount

    return Balance(
        sender.contract_balance
        - sender.total_withdraw
        - sender_transferred_amount
        + receiver_transferred_amount
    )


def get_current_balanceproof(end_state: NettingChannelEndState) -> BalanceProofData:
    balance_proof = end_state.balance_proof

    if balance_proof:
        locksroot = balance_proof.locksroot
        nonce = end_state.nonce
        transferred_amount = balance_proof.transferred_amount
        locked_amount = get_amount_locked(end_state)
    else:
        locksroot = Locksroot(LOCKSROOT_OF_NO_LOCKS)
        nonce = Nonce(0)
        transferred_amount = TokenAmount(0)
        locked_amount = TokenAmount(0)

    return locksroot, nonce, transferred_amount, locked_amount


def get_current_nonce(end_state: NettingChannelEndState) -> Nonce:
    return end_state.nonce


def get_distributable(
    sender: NettingChannelEndState, receiver: NettingChannelEndState
) -> TokenAmount:
    """Return the amount of tokens that can be used by the `sender`.

    The returned value is limited to a UINT256, since that is the representation
    used in the smart contracts and we cannot use a larger value. The limit is
    enforced on transferred_amount + locked_amount to avoid overflows. This is
    an additional security check.
    """
    _, _, transferred_amount, locked_amount = get_current_balanceproof(sender)

    distributable = get_balance(sender, receiver) - get_amount_locked(sender)

    overflow_limit = max(UINT256_MAX - transferred_amount - locked_amount, 0)

    return TokenAmount(min(overflow_limit, distributable))


def get_batch_unlock(end_state: NettingChannelEndState,) -> Optional[PendingLocksState]:
    """ Unlock proof for entire pending locks

    The unlock proof contains all the locks, tightly packed, needed by the token
    network contract to verify the secret expiry and calculate the token amounts to transfer.
    """

    if len(end_state.pending_locks.locks) == 0:  # pylint: disable=len-as-condition
        return None
    return end_state.pending_locks


def get_lock(
    end_state: NettingChannelEndState, secrethash: SecretHash
) -> Optional[HashTimeLockState]:
    """Return the lock correspoding to `secrethash` or None if the lock is
    unknown.
    """
    lock = end_state.secrethashes_to_lockedlocks.get(secrethash)

    if not lock:
        partial_unlock = end_state.secrethashes_to_unlockedlocks.get(secrethash)

        if not partial_unlock:
            partial_unlock = end_state.secrethashes_to_onchain_unlockedlocks.get(secrethash)

        if partial_unlock:
            lock = partial_unlock.lock

    assert isinstance(lock, HashTimeLockState) or lock is None
    return lock


def lock_exists_in_either_channel_side(
    channel_state: NettingChannelState, secrethash: SecretHash
) -> bool:
    """Check if the lock with `secrethash` exists in either our state or the partner's state"""
    lock = get_lock(channel_state.our_state, secrethash)
    if not lock:
        lock = get_lock(channel_state.partner_state, secrethash)
    return lock is not None


def get_next_nonce(end_state: NettingChannelEndState) -> Nonce:
    # 0 must not be used since in the netting contract it represents null.
    return Nonce(end_state.nonce + 1)


def get_number_of_pending_transfers(channel_end_state: NettingChannelEndState) -> int:
    return len(channel_end_state.pending_locks.locks)


def get_status(channel_state: NettingChannelState) -> str:
    if channel_state.settle_transaction:
        finished_successfully = (
            channel_state.settle_transaction.result == TransactionExecutionStatus.SUCCESS
        )
        running = channel_state.settle_transaction.finished_block_number is None

        if finished_successfully:
            result = CHANNEL_STATE_SETTLED
        elif running:
            result = CHANNEL_STATE_SETTLING
        else:
            result = CHANNEL_STATE_UNUSABLE

    elif channel_state.close_transaction:
        finished_successfully = (
            channel_state.close_transaction.result == TransactionExecutionStatus.SUCCESS
        )
        running = channel_state.close_transaction.finished_block_number is None

        if finished_successfully:
            result = CHANNEL_STATE_CLOSED
        elif running:
            result = CHANNEL_STATE_CLOSING
        else:
            result = CHANNEL_STATE_UNUSABLE

    else:
        result = CHANNEL_STATE_OPENED

    return result


def _del_unclaimed_lock(end_state: NettingChannelEndState, secrethash: SecretHash) -> None:
    if secrethash in end_state.secrethashes_to_lockedlocks:
        del end_state.secrethashes_to_lockedlocks[secrethash]

    if secrethash in end_state.secrethashes_to_unlockedlocks:
        del end_state.secrethashes_to_unlockedlocks[secrethash]


def _del_lock(end_state: NettingChannelEndState, secrethash: SecretHash) -> None:
    """Removes the lock from the indexing structures.

    Note:
        This won't change the pending locks!
    """
    assert is_lock_pending(end_state, secrethash)

    _del_unclaimed_lock(end_state, secrethash)

    if secrethash in end_state.secrethashes_to_onchain_unlockedlocks:
        del end_state.secrethashes_to_onchain_unlockedlocks[secrethash]


def set_closed(channel_state: NettingChannelState, block_number: BlockNumber) -> None:
    if not channel_state.close_transaction:
        channel_state.close_transaction = TransactionExecutionStatus(
            None, block_number, TransactionExecutionStatus.SUCCESS
        )

    elif not channel_state.close_transaction.finished_block_number:
        channel_state.close_transaction.finished_block_number = block_number
        channel_state.close_transaction.result = TransactionExecutionStatus.SUCCESS


def set_settled(channel_state: NettingChannelState, block_number: BlockNumber) -> None:
    if not channel_state.settle_transaction:
        channel_state.settle_transaction = TransactionExecutionStatus(
            None, block_number, TransactionExecutionStatus.SUCCESS
        )

    elif not channel_state.settle_transaction.finished_block_number:
        channel_state.settle_transaction.finished_block_number = block_number
        channel_state.settle_transaction.result = TransactionExecutionStatus.SUCCESS


def update_contract_balance(end_state: NettingChannelEndState, contract_balance: Balance) -> None:
    if contract_balance > end_state.contract_balance:
        end_state.contract_balance = contract_balance


def compute_locks_with(
    locks: PendingLocksState, lock: Union[HashTimeLockState, UnlockPartialProofState]
) -> Optional[PendingLocksState]:
    """Register the given lock with as a pending locks."""
    if bytes(lock.encoded) not in locks.locks:
        locks = PendingLocksState(list(locks.locks))
        locks.locks.append(EncodedData(bytes(lock.encoded)))  # pylint: disable=E1101
        return locks
    else:
        return None


def compute_locks_without(
    locks: PendingLocksState, lock_encoded: EncodedData
) -> Optional[PendingLocksState]:
    # Use None to inform the caller the lock is unknown
    if lock_encoded in locks.locks:
        locks = PendingLocksState(list(locks.locks))
        locks.locks.remove(lock_encoded)
        return locks
    else:
        return None


def compute_locksroot(locks: PendingLocksState) -> Locksroot:
    """ Compute the hash representing all pending locks
    The hash is submitted in TokenNetwork.settleChannel() call.
    """
    return Locksroot(keccak(b"".join(locks.locks)))


def create_sendlockedtransfer(
    channel_state: NettingChannelState,
    initiator: InitiatorAddress,
    target: TargetAddress,
    amount: PaymentWithFeeAmount,
    message_identifier: MessageID,
    payment_identifier: PaymentID,
    expiration: BlockExpiration,
    secrethash: SecretHash,
    route_states: List[RouteState],
) -> Tuple[SendLockedTransfer, PendingLocksState]:
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state
    our_balance_proof = our_state.balance_proof

    msg = "caller must make sure there is enough balance"
    assert amount <= get_distributable(our_state, partner_state), msg

    msg = "caller must make sure the channel is open"
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    lock = HashTimeLockState(amount=amount, expiration=expiration, secrethash=secrethash)

    pending_locks = compute_locks_with(channel_state.our_state.pending_locks, lock)
    # The caller must ensure the same lock is not being used twice
    assert pending_locks, "lock is already registered"

    locksroot = compute_locksroot(pending_locks)

    if our_balance_proof:
        transferred_amount = our_balance_proof.transferred_amount
    else:
        transferred_amount = TokenAmount(0)

    msg = "caller must make sure the result wont overflow"
    assert transferred_amount + amount <= UINT256_MAX, msg

    token = channel_state.token_address
    recipient = channel_state.partner_state.address
    # the new lock is not registered yet
    locked_amount = TokenAmount(get_amount_locked(our_state) + amount)

    nonce = get_next_nonce(channel_state.our_state)

    balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        canonical_identifier=channel_state.canonical_identifier,
    )

    locked_transfer = LockedTransferUnsignedState(
        payment_identifier=payment_identifier,
        token=token,
        balance_proof=balance_proof,
        lock=lock,
        initiator=initiator,
        target=target,
        route_states=route_states,
    )

    lockedtransfer = SendLockedTransfer(
        recipient=recipient,
        message_identifier=message_identifier,
        transfer=locked_transfer,
        canonical_identifier=channel_state.canonical_identifier,
    )

    return lockedtransfer, pending_locks


def create_unlock(
    channel_state: NettingChannelState,
    message_identifier: MessageID,
    payment_identifier: PaymentID,
    secret: Secret,
    lock: HashTimeLockState,
) -> SendUnlockAndPendingLocksState:
    our_state = channel_state.our_state

    msg = "caller must make sure the lock is known"
    assert is_lock_pending(our_state, lock.secrethash), msg

    msg = "caller must make sure the channel is open"
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    our_balance_proof = our_state.balance_proof
    msg = "the lock is pending, it must be in the pending locks"
    assert our_balance_proof is not None, msg
    transferred_amount = TokenAmount(lock.amount + our_balance_proof.transferred_amount)

    pending_locks = compute_locks_without(
        our_state.pending_locks, EncodedData(bytes(lock.encoded))
    )
    msg = "the lock is pending, it must be in the pending locks"
    assert pending_locks is not None, msg

    locksroot = compute_locksroot(pending_locks)

    token_address = channel_state.token_address
    recipient = channel_state.partner_state.address
    # the lock is still registered
    locked_amount = TokenAmount(get_amount_locked(our_state) - lock.amount)

    nonce = get_next_nonce(our_state)
    channel_state.our_state.nonce = nonce

    balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        canonical_identifier=channel_state.canonical_identifier,
    )

    unlock_lock = SendBalanceProof(
        recipient=recipient,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        token_address=token_address,
        secret=secret,
        balance_proof=balance_proof,
        canonical_identifier=channel_state.canonical_identifier,
    )

    return unlock_lock, pending_locks


def send_lockedtransfer(
    channel_state: NettingChannelState,
    initiator: InitiatorAddress,
    target: TargetAddress,
    amount: PaymentWithFeeAmount,
    message_identifier: MessageID,
    payment_identifier: PaymentID,
    expiration: BlockExpiration,
    secrethash: SecretHash,
    route_states: List[RouteState],
) -> SendLockedTransfer:
    send_locked_transfer_event, pending_locks = create_sendlockedtransfer(
        channel_state=channel_state,
        initiator=initiator,
        target=target,
        amount=amount,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        expiration=expiration,
        secrethash=secrethash,
        route_states=route_states,
    )

    transfer = send_locked_transfer_event.transfer
    lock = transfer.lock
    channel_state.our_state.balance_proof = transfer.balance_proof
    channel_state.our_state.nonce = transfer.balance_proof.nonce
    channel_state.our_state.pending_locks = pending_locks
    channel_state.our_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

    return send_locked_transfer_event


def send_refundtransfer(
    channel_state: NettingChannelState,
    initiator: InitiatorAddress,
    target: TargetAddress,
    amount: PaymentWithFeeAmount,
    message_identifier: MessageID,
    payment_identifier: PaymentID,
    expiration: BlockExpiration,
    secrethash: SecretHash,
    route_state: RouteState,
) -> SendRefundTransfer:
    msg = "Refunds are only valid for *known and pending* transfers"
    assert secrethash in channel_state.partner_state.secrethashes_to_lockedlocks, msg

    msg = "caller must make sure the channel is open"
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    send_mediated_transfer, pending_locks = create_sendlockedtransfer(
        channel_state=channel_state,
        initiator=initiator,
        target=target,
        amount=amount,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        expiration=expiration,
        secrethash=secrethash,
        route_states=[route_state],
    )

    mediated_transfer = send_mediated_transfer.transfer
    lock = mediated_transfer.lock

    channel_state.our_state.balance_proof = mediated_transfer.balance_proof
    channel_state.our_state.nonce = mediated_transfer.balance_proof.nonce
    channel_state.our_state.pending_locks = pending_locks
    channel_state.our_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

    refund_transfer = refund_from_sendmediated(send_mediated_transfer)
    return refund_transfer


def send_unlock(
    channel_state: NettingChannelState,
    message_identifier: MessageID,
    payment_identifier: PaymentID,
    secret: Secret,
    secrethash: SecretHash,
) -> SendBalanceProof:
    lock = get_lock(channel_state.our_state, secrethash)
    assert lock, "caller must ensure the lock exists"

    unlock, pending_locks = create_unlock(
        channel_state, message_identifier, payment_identifier, secret, lock
    )

    channel_state.our_state.balance_proof = unlock.balance_proof
    channel_state.our_state.pending_locks = pending_locks

    _del_lock(channel_state.our_state, lock.secrethash)

    return unlock


def events_for_close(
    channel_state: NettingChannelState, block_number: BlockNumber, block_hash: BlockHash
) -> List[Event]:
    events: List[Event] = list()

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED:
        channel_state.close_transaction = TransactionExecutionStatus(block_number, None, None)

        balance_proof = channel_state.partner_state.balance_proof
        # silence mypy: partner's balance proofs should be signed
        assert balance_proof is None or isinstance(balance_proof, BalanceProofSignedState)

        close_event = ContractSendChannelClose(
            canonical_identifier=channel_state.canonical_identifier,
            balance_proof=balance_proof,
            triggered_by_block_hash=block_hash,
        )

        events.append(close_event)

    return events


def send_withdraw_request(
    channel_state: NettingChannelState,
    withdraw_state: WithdrawState,
    pseudo_random_generator: random.Random,
) -> List[Event]:
    events: List[Event] = list()

    if get_status(channel_state) not in CHANNEL_STATES_PRIOR_TO_CLOSED:
        return events

    withdraw_event = SendWithdrawRequest(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=channel_state.chain_id,
            token_network_address=channel_state.token_network_address,
            channel_identifier=channel_state.identifier,
        ),
        recipient=channel_state.partner_state.address,
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        total_withdraw=withdraw_state.total_withdraw,
        participant=channel_state.our_state.address,
        nonce=channel_state.our_state.nonce,
    )

    events.append(withdraw_event)

    return events


def create_sendexpiredlock(
    sender_end_state: NettingChannelEndState,
    locked_lock: LockType,
    pseudo_random_generator: random.Random,
    chain_id: ChainID,
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    recipient: Address,
) -> Tuple[Optional[SendLockExpired], Optional[PendingLocksState]]:
    locked_amount = get_amount_locked(sender_end_state)
    balance_proof = sender_end_state.balance_proof
    updated_locked_amount = TokenAmount(locked_amount - locked_lock.amount)

    assert balance_proof is not None, "there should be a balance proof because a lock is expiring"
    transferred_amount = balance_proof.transferred_amount

    pending_locks = compute_locks_without(
        sender_end_state.pending_locks, EncodedData(bytes(locked_lock.encoded))
    )

    if not pending_locks:
        return None, None

    nonce = get_next_nonce(sender_end_state)

    locksroot = compute_locksroot(pending_locks)

    balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=updated_locked_amount,
        locksroot=locksroot,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )

    send_lock_expired = SendLockExpired(
        recipient=recipient,
        canonical_identifier=balance_proof.canonical_identifier,
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        balance_proof=balance_proof,
        secrethash=locked_lock.secrethash,
    )

    return send_lock_expired, pending_locks


def send_lock_expired(
    channel_state: NettingChannelState,
    locked_lock: LockType,
    pseudo_random_generator: random.Random,
) -> List[SendLockExpired]:
    msg = "caller must make sure the channel is open"
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    send_lock_expired, pending_locks = create_sendexpiredlock(
        sender_end_state=channel_state.our_state,
        locked_lock=locked_lock,
        pseudo_random_generator=pseudo_random_generator,
        chain_id=channel_state.chain_id,
        token_network_address=channel_state.token_network_address,
        channel_identifier=channel_state.identifier,
        recipient=channel_state.partner_state.address,
    )

    if send_lock_expired:
        assert pending_locks, "create_sendexpiredlock should return both message and pending locks"
        channel_state.our_state.pending_locks = pending_locks
        channel_state.our_state.balance_proof = send_lock_expired.balance_proof
        channel_state.our_state.nonce = send_lock_expired.balance_proof.nonce

        _del_unclaimed_lock(channel_state.our_state, locked_lock.secrethash)

        return [send_lock_expired]

    return []


def is_withdraw_expired(
    block_number: BlockNumber, expiration_threshold: BlockNumber
) -> bool:
    """ Determine whether a withdraw has expired.

    The withdraw has expired if the current block exceeds
    the withdraw's expiration + confirmation blocks.
    """
    if block_number < expiration_threshold:
        return False

    return True


def events_for_expired_withdraws(
    channel_state: NettingChannelState,
    block_number: BlockNumber,
    pseudo_random_generator: random.Random,
) -> List[SendWithdrawExpired]:
    events: List[SendWithdrawExpired] = list()

    for withdraw_state in channel_state.our_state.withdraws:
        withdraw_expired = is_withdraw_expired(
            block_number=block_number,
            expiration_threshold=get_sender_expiration_threshold(withdraw_state.expiration),
        )

        # Break on the first non-expired withdraw as the list
        # of withdraws are ordered and only ealier withdraws
        # can expire.
        if not withdraw_expired:
            break

        events.append(
            SendWithdrawExpired(
                recipient=channel_state.partner_state.address,
                canonical_identifier=channel_state.canonical_identifier,
                message_identifier=message_identifier_from_prng(pseudo_random_generator),
                total_withdraw=withdraw_state.total_withdraw,
                participant=channel_state.our_state.address,
                nonce=get_next_nonce(channel_state.our_state),
            )
        )
    return events


def register_secret_endstate(
    end_state: NettingChannelEndState, secret: Secret, secrethash: SecretHash
) -> None:
    if is_lock_locked(end_state, secrethash):
        pending_lock = end_state.secrethashes_to_lockedlocks[secrethash]
        del end_state.secrethashes_to_lockedlocks[secrethash]

        end_state.secrethashes_to_unlockedlocks[secrethash] = UnlockPartialProofState(
            pending_lock, secret
        )


def register_onchain_secret_endstate(
    end_state: NettingChannelEndState,
    secret: Secret,
    secrethash: SecretHash,
    secret_reveal_block_number: BlockNumber,
    delete_lock: bool = True,
) -> None:
    # the lock might be in end_state.secrethashes_to_lockedlocks or
    # end_state.secrethashes_to_unlockedlocks
    # It should be removed from both and moved into secrethashes_to_onchain_unlockedlocks
    pending_lock: Optional[HashTimeLockState] = None

    if is_lock_locked(end_state, secrethash):
        pending_lock = end_state.secrethashes_to_lockedlocks[secrethash]

    if secrethash in end_state.secrethashes_to_unlockedlocks:
        pending_lock = end_state.secrethashes_to_unlockedlocks[secrethash].lock

    if pending_lock:
        # If pending lock is still locked or unlocked but unclaimed
        # And has expired before the on-chain secret reveal was mined,
        # Then we simply reject on-chain secret reveal
        if pending_lock.expiration < secret_reveal_block_number:
            return

        if delete_lock:
            _del_lock(end_state, secrethash)

        end_state.secrethashes_to_onchain_unlockedlocks[secrethash] = UnlockPartialProofState(
            pending_lock, secret
        )


def register_offchain_secret(
    channel_state: NettingChannelState, secret: Secret, secrethash: SecretHash
) -> None:
    """This will register the secret and set the lock to the unlocked stated.

    Even though the lock is unlock it is *not* claimed. The capacity will
    increase once the next balance proof is received.
    """
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state

    register_secret_endstate(our_state, secret, secrethash)
    register_secret_endstate(partner_state, secret, secrethash)


def register_onchain_secret(
    channel_state: NettingChannelState,
    secret: Secret,
    secrethash: SecretHash,
    secret_reveal_block_number: BlockNumber,
    delete_lock: bool = True,
) -> None:
    """This will register the onchain secret and set the lock to the unlocked stated.

    Even though the lock is unlocked it is *not* claimed. The capacity will
    increase once the next balance proof is received.
    """
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state

    register_onchain_secret_endstate(
        our_state, secret, secrethash, secret_reveal_block_number, delete_lock
    )
    register_onchain_secret_endstate(
        partner_state, secret, secrethash, secret_reveal_block_number, delete_lock
    )


def handle_action_close(
    channel_state: NettingChannelState,
    close: ActionChannelClose,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> TransitionResult[NettingChannelState]:
    msg = "caller must make sure the ids match"
    assert channel_state.identifier == close.channel_identifier, msg

    events = events_for_close(
        channel_state=channel_state, block_number=block_number, block_hash=block_hash
    )
    return TransitionResult(channel_state, events)


def handle_action_update_fee(
    channel_state: NettingChannelState, update_fee: ActionChannelUpdateFee
) -> TransitionResult[NettingChannelState]:
    msg = "caller must make sure the ids match"
    assert channel_state.canonical_identifier == update_fee.canonical_identifier, msg

    channel_state.fee_schedule.flat = update_fee.flat_fee
    channel_state.fee_schedule.proportional = update_fee.proportional_fee

    if update_fee.use_imbalance_penalty:
        channel_state.fee_schedule.imbalance_penalty = calculate_imbalance_fees(
            channel_capacity=get_capacity(channel_state)
        )

    return TransitionResult(channel_state, list())


def handle_action_withdraw(
    channel_state: NettingChannelState,
    action_withdraw: ActionChannelWithdraw,
    pseudo_random_generator: random.Random,
    block_number: BlockNumber,
) -> TransitionResult[NettingChannelState]:
    events: List[Event] = list()
    is_valid, msg = is_valid_action_withdraw(channel_state, action_withdraw)

    if is_valid:
        nonce = get_next_nonce(channel_state.our_state)
        # Calculate the withdraw's expiry exactly the same as we
        # do for lock.
        # That value defines how many blocks it takes for a transaction to be
        # mined under congestion.
        # An expiration lower than 1 * reveal_timeout  means that we are requesting
        # a withdraw that will fail under congestion.
        # A value larger then 2 * reveal_timeout means Raiden would be slower
        # than the blockchain.
        expiration = get_safe_initial_expiration(
            block_number=block_number, reveal_timeout=channel_state.reveal_timeout
        )
        withdraw_state = WithdrawState(
            total_withdraw=action_withdraw.total_withdraw, nonce=nonce, expiration=expiration
        )
        channel_state.our_state.total_withdraw = action_withdraw.total_withdraw
        channel_state.our_state.nonce = nonce
        channel_state.our_state.withdraws.append(withdraw_state)

        events = send_withdraw_request(
            channel_state=channel_state,
            withdraw_state=withdraw_state,
            pseudo_random_generator=pseudo_random_generator,
        )
    else:
        assert msg, "is_valid_action_withdraw should return error msg if not valid"
        events = [
            EventInvalidActionWithdraw(
                attempted_withdraw=action_withdraw.total_withdraw, reason=msg
            )
        ]

    return TransitionResult(channel_state, events)


def handle_receive_withdraw_request(
    channel_state: NettingChannelState, withdraw_request: ReceiveWithdrawRequest
) -> TransitionResult[NettingChannelState]:
    is_valid, msg = is_valid_withdraw_request(
        channel_state=channel_state, withdraw_request=withdraw_request
    )
    if is_valid:
        withdraw_state = WithdrawState(
            total_withdraw=withdraw_request.total_withdraw,
            nonce=withdraw_request.nonce,
            # Expiration for a received request is set to 0,
            # as only the sender can instruct the current node
            # to expire the withdraw.
            expiration=BlockExpiration(0),
        )
        channel_state.partner_state.withdraws.append(withdraw_state)
        channel_state.partner_state.total_withdraw = withdraw_request.total_withdraw
        channel_state.partner_state.nonce = withdraw_request.nonce

        channel_state.our_state.nonce = get_next_nonce(channel_state.our_state)
        send_withdraw = SendWithdrawConfirmation(
            canonical_identifier=channel_state.canonical_identifier,
            recipient=channel_state.partner_state.address,
            message_identifier=withdraw_request.message_identifier,
            total_withdraw=withdraw_request.total_withdraw,
            participant=channel_state.partner_state.address,
            nonce=channel_state.our_state.nonce,
        )

        events: List[Event] = [send_withdraw]
    else:
        assert msg, "is_valid_withdraw_request should return error msg if not valid"
        invalid_withdraw_request = EventInvalidReceivedWithdrawRequest(
            attempted_withdraw=withdraw_request.total_withdraw, reason=msg
        )
        events = [invalid_withdraw_request]

    return TransitionResult(channel_state, events)


def handle_receive_withdraw_confirmation(
    channel_state: NettingChannelState,
    withdraw: ReceiveWithdrawConfirmation,
    block_hash: BlockHash,
) -> TransitionResult[NettingChannelState]:
    events: List[Event] = list()

    is_valid, msg = is_valid_withdraw_confirmation(channel_state=channel_state, withdraw=withdraw)
    if is_valid:
        channel_state.partner_state.nonce = withdraw.nonce
        events.extend(
            [
                ContractSendChannelWithdraw(
                    canonical_identifier=withdraw.canonical_identifier,
                    total_withdraw=withdraw.total_withdraw,
                    partner_signature=withdraw.signature,
                    triggered_by_block_hash=block_hash,
                ),
                SendProcessed(
                    recipient=channel_state.partner_state.address,
                    message_identifier=withdraw.message_identifier,
                    canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
                ),
            ]
        )
    else:
        assert msg, "is_valid_withdraw_confirmation should return error msg if not valid"
        invalid_withdraw = EventInvalidReceivedWithdraw(
            attempted_withdraw=withdraw.total_withdraw, reason=msg
        )
        events = [invalid_withdraw]

    return TransitionResult(channel_state, events)


def handle_receive_withdraw_expired(
    channel_state: NettingChannelState,
    withdraw_expired: ReceiveWithdrawExpired,
    block_number: BlockNumber,
) -> TransitionResult:
    events: List[Event] = list()

    withdraw_states = filter(
        lambda state: state.total_withdraw == withdraw_expired.total_withdraw,
        channel_state.partner_state.withdraws,
    )

    if not withdraw_states:
        invalid_withdraw_expired_msg = (
            f"Withdraw expired of {withdraw_expired.total_withdraw} "
            f"did not correspond to previous withdraw request"
        )
        return TransitionResult(
            channel_state,
            [
                EventInvalidReceivedWithdrawExpired(
                    attempted_withdraw=withdraw_expired.total_withdraw,
                    reason=invalid_withdraw_expired_msg,
                )
            ],
        )

    # Take the first withdraw state found because
    # withdraw expiry happens in order of which
    # withdraws have been triggered.
    withdraw_state = next(withdraw_states)

    is_valid, msg = is_valid_withdraw_expired(
        channel_state=channel_state,
        state_change=withdraw_expired,
        withdraw_state=withdraw_state,
        block_number=block_number,
    )
    if is_valid:
        withdraws = channel_state.partner_state.withdraws
        withdraws.remove(withdraw_state)

        # Since total_withdraw is monotonic, receiving withdraw
        # expiration means that the new total_withdraw becomes
        # the latest known non-expired value.
        if not withdraws:
            channel_state.partner_state.total_withdraw = WithdrawAmount(0)
        else:
            channel_state.partner_state.total_withdraw = WithdrawAmount(
                withdraws[-1].total_withdraw
            )

        channel_state.partner_state.nonce = withdraw_expired.nonce

        send_processed = SendProcessed(
            recipient=channel_state.partner_state.address,
            message_identifier=withdraw_expired.message_identifier,
            canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
        )
        events = [send_processed]
    else:
        assert msg, "is_valid_withdraw_expired should return error msg if not valid"
        invalid_withdraw_expired = EventInvalidReceivedWithdrawExpired(
            attempted_withdraw=withdraw_expired.total_withdraw, reason=msg
        )
        events = [invalid_withdraw_expired]

    return TransitionResult(channel_state, events)


def handle_refundtransfer(
    received_transfer: LockedTransferUnsignedState,
    channel_state: NettingChannelState,
    refund: ReceiveTransferRefund,
) -> EventsOrError:
    events: List[Event]
    is_valid, msg, pending_locks = is_valid_refund(
        refund=refund,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
        receiver_state=channel_state.our_state,
        received_transfer=received_transfer,
    )
    if is_valid:
        assert pending_locks, "is_valid_refund should return pending locks if valid"
        channel_state.partner_state.balance_proof = refund.transfer.balance_proof
        channel_state.partner_state.nonce = refund.transfer.balance_proof.nonce
        channel_state.partner_state.pending_locks = pending_locks

        lock = refund.transfer.lock
        channel_state.partner_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

        send_processed = SendProcessed(
            recipient=refund.transfer.balance_proof.sender,
            message_identifier=refund.transfer.message_identifier,
            canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
        )
        events = [send_processed]
    else:
        assert msg, "is_valid_refund should return error msg if not valid"
        invalid_refund = EventInvalidReceivedTransferRefund(
            payment_identifier=received_transfer.payment_identifier, reason=msg
        )
        events = [invalid_refund]

    return is_valid, events, msg


def handle_receive_lock_expired(
    channel_state: NettingChannelState, state_change: ReceiveLockExpired, block_number: BlockNumber
) -> TransitionResult[NettingChannelState]:
    """Remove expired locks from channel states."""
    is_valid, msg, pending_locks = is_valid_lock_expired(
        state_change=state_change,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
        receiver_state=channel_state.our_state,
        block_number=block_number,
    )

    events: List[Event] = list()
    if is_valid:
        assert pending_locks, "is_valid_lock_expired should return pending locks if valid"
        channel_state.partner_state.balance_proof = state_change.balance_proof
        channel_state.partner_state.nonce = state_change.balance_proof.nonce
        channel_state.partner_state.pending_locks = pending_locks

        _del_unclaimed_lock(channel_state.partner_state, state_change.secrethash)

        send_processed = SendProcessed(
            recipient=state_change.balance_proof.sender,
            message_identifier=state_change.message_identifier,
            canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
        )
        events = [send_processed]
    else:
        assert msg, "is_valid_lock_expired should return error msg if not valid"
        invalid_lock_expired = EventInvalidReceivedLockExpired(
            secrethash=state_change.secrethash, reason=msg
        )
        events = [invalid_lock_expired]

    return TransitionResult(channel_state, events)


def handle_receive_lockedtransfer(
    channel_state: NettingChannelState, mediated_transfer: LockedTransferSignedState
) -> EventsOrError:
    """Register the latest known transfer.

    The receiver needs to use this method to update the container with a
    _valid_ transfer, otherwise the locksroot will not contain the pending
    transfer. The receiver needs to ensure that the locksroot has the
    secrethash included, otherwise it won't be able to claim it.
    """
    events: List[Event]
    is_valid, msg, pending_locks = is_valid_lockedtransfer(
        mediated_transfer, channel_state, channel_state.partner_state, channel_state.our_state
    )

    if is_valid:
        assert pending_locks, "is_valid_lock_expired should return pending locks if valid"
        channel_state.partner_state.balance_proof = mediated_transfer.balance_proof
        channel_state.partner_state.nonce = mediated_transfer.balance_proof.nonce
        channel_state.partner_state.pending_locks = pending_locks

        lock = mediated_transfer.lock
        channel_state.partner_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

        send_processed = SendProcessed(
            recipient=mediated_transfer.balance_proof.sender,
            message_identifier=mediated_transfer.message_identifier,
            canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
        )
        events = [send_processed]
    else:
        assert msg, "is_valid_lock_expired should return error msg if not valid"
        invalid_locked = EventInvalidReceivedLockedTransfer(
            payment_identifier=mediated_transfer.payment_identifier, reason=msg
        )
        events = [invalid_locked]

    return is_valid, events, msg


def handle_receive_refundtransfercancelroute(
    channel_state: NettingChannelState, refund_transfer: LockedTransferSignedState
) -> EventsOrError:
    return handle_receive_lockedtransfer(channel_state, refund_transfer)


def handle_unlock(channel_state: NettingChannelState, unlock: ReceiveUnlock) -> EventsOrError:
    is_valid, msg, unlocked_pending_locks = is_valid_unlock(
        unlock, channel_state, channel_state.partner_state
    )

    if is_valid:
        assert (
            unlocked_pending_locks is not None
        ), "is_valid_unlock should return pending locks if valid"
        channel_state.partner_state.balance_proof = unlock.balance_proof
        channel_state.partner_state.nonce = unlock.balance_proof.nonce
        channel_state.partner_state.pending_locks = unlocked_pending_locks

        _del_lock(channel_state.partner_state, unlock.secrethash)

        send_processed = SendProcessed(
            recipient=unlock.balance_proof.sender,
            message_identifier=unlock.message_identifier,
            canonical_identifier=CANONICAL_IDENTIFIER_GLOBAL_QUEUE,
        )
        events: List[Event] = [send_processed]
    else:
        assert msg, "is_valid_unlock should return error msg if not valid"
        invalid_unlock = EventInvalidReceivedUnlock(secrethash=unlock.secrethash, reason=msg)
        events = [invalid_unlock]

    return is_valid, events, msg


def handle_block(
    channel_state: NettingChannelState,
    state_change: Block,
    block_number: BlockNumber,
    pseudo_random_generator: random.Random,
) -> TransitionResult[NettingChannelState]:
    assert state_change.block_number == block_number

    events: List[Event] = list()

    expired_withdraws = events_for_expired_withdraws(
        channel_state=channel_state,
        block_number=block_number,
        pseudo_random_generator=pseudo_random_generator,
    )
    events.extend(expired_withdraws)

    if get_status(channel_state) == CHANNEL_STATE_CLOSED:
        msg = "channel get_status is STATE_CLOSED, but close_transaction is not set"
        assert channel_state.close_transaction, msg
        msg = "channel get_status is STATE_CLOSED, but close_transaction block number is missing"
        assert channel_state.close_transaction.finished_block_number, msg

        closed_block_number = channel_state.close_transaction.finished_block_number
        settlement_end = closed_block_number + channel_state.settle_timeout

        if state_change.block_number > settlement_end:
            channel_state.settle_transaction = TransactionExecutionStatus(
                state_change.block_number, None, None
            )
            event = ContractSendChannelSettle(
                canonical_identifier=channel_state.canonical_identifier,
                triggered_by_block_hash=state_change.block_hash,
            )
            events.append(event)

    while is_deposit_confirmed(channel_state, block_number):
        order_deposit_transaction = heapq.heappop(channel_state.deposit_transaction_queue)
        apply_channel_newbalance(channel_state, order_deposit_transaction.transaction)

    return TransitionResult(channel_state, events)


def handle_channel_closed(
    channel_state: NettingChannelState, state_change: ContractReceiveChannelClosed
) -> TransitionResult[NettingChannelState]:
    events: List[Event] = list()

    just_closed = (
        state_change.channel_identifier == channel_state.identifier
        and get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED
    )

    if just_closed:
        set_closed(channel_state, state_change.block_number)

        balance_proof = channel_state.partner_state.balance_proof
        call_update = (
            state_change.transaction_from != channel_state.our_state.address
            and balance_proof is not None
            and channel_state.update_transaction is None
        )
        if call_update:
            expiration = BlockExpiration(state_change.block_number + channel_state.settle_timeout)
            # silence mypy: partner's balance proof is always signed
            assert isinstance(balance_proof, BalanceProofSignedState)
            # The channel was closed by our partner, if there is a balance
            # proof available update this node half of the state
            update = ContractSendChannelUpdateTransfer(
                expiration=expiration,
                balance_proof=balance_proof,
                triggered_by_block_hash=state_change.block_hash,
            )
            channel_state.update_transaction = TransactionExecutionStatus(
                started_block_number=state_change.block_number,
                finished_block_number=None,
                result=None,
            )
            events.append(update)

    return TransitionResult(channel_state, events)


def handle_channel_updated_transfer(
    channel_state: NettingChannelState,
    state_change: ContractReceiveUpdateTransfer,
    block_number: BlockNumber,
) -> TransitionResult[NettingChannelState]:
    if state_change.channel_identifier == channel_state.identifier:
        # update transfer was called, make sure we don't call it again
        channel_state.update_transaction = TransactionExecutionStatus(
            started_block_number=None,
            finished_block_number=block_number,
            result=TransactionExecutionStatus.SUCCESS,
        )

    return TransitionResult(channel_state, list())


def handle_channel_settled(
    channel_state: NettingChannelState, state_change: ContractReceiveChannelSettled
) -> TransitionResult[Optional[NettingChannelState]]:
    events: List[Event] = list()

    if state_change.channel_identifier == channel_state.identifier:
        set_settled(channel_state, state_change.block_number)

        our_locksroot = state_change.our_onchain_locksroot
        partner_locksroot = state_change.partner_onchain_locksroot

        should_clear_channel = (
            our_locksroot == LOCKSROOT_OF_NO_LOCKS and partner_locksroot == LOCKSROOT_OF_NO_LOCKS
        )

        if should_clear_channel:
            return TransitionResult(None, events)

        channel_state.our_state.onchain_locksroot = our_locksroot
        channel_state.partner_state.onchain_locksroot = partner_locksroot

        onchain_unlock = ContractSendChannelBatchUnlock(
            canonical_identifier=channel_state.canonical_identifier,
            sender=channel_state.partner_state.address,
            triggered_by_block_hash=state_change.block_hash,
        )
        events.append(onchain_unlock)

    return TransitionResult(channel_state, events)


def handle_channel_newbalance(
    channel_state: NettingChannelState,
    state_change: ContractReceiveChannelNewBalance,
    block_number: BlockNumber,
) -> TransitionResult[NettingChannelState]:
    deposit_transaction = state_change.deposit_transaction

    if is_transaction_confirmed(deposit_transaction.deposit_block_number, block_number):
        apply_channel_newbalance(channel_state, state_change.deposit_transaction)
    else:
        order = TransactionOrder(deposit_transaction.deposit_block_number, deposit_transaction)
        heapq.heappush(channel_state.deposit_transaction_queue, order)

    events: List[Event] = list()
    return TransitionResult(channel_state, events)


def apply_channel_newbalance(
    channel_state: NettingChannelState, deposit_transaction: TransactionChannelNewBalance
) -> None:
    participant_address = deposit_transaction.participant_address
    contract_balance = Balance(deposit_transaction.contract_balance)

    if participant_address == channel_state.our_state.address:
        update_contract_balance(channel_state.our_state, contract_balance)
    elif participant_address == channel_state.partner_state.address:
        update_contract_balance(channel_state.partner_state, contract_balance)


def handle_channel_withdraw(
    channel_state: NettingChannelState, state_change: ContractReceiveChannelWithdraw
) -> TransitionResult[NettingChannelState]:
    # pylint: disable=unused-argument

    # Currently, the state machine doesn't need to process this event.
    # NOTE: Keep until withdraw expiration is implemented
    events: List[Event] = list()
    return TransitionResult(channel_state, events)


def handle_channel_batch_unlock(
    channel_state: NettingChannelState, state_change: ContractReceiveChannelBatchUnlock
) -> TransitionResult[Optional[NettingChannelState]]:
    events: List[Event] = list()

    new_channel_state: Optional[NettingChannelState] = channel_state
    # Unlock is allowed by the smart contract only on a settled channel.
    # Ignore the unlock if the channel was not closed yet.
    if get_status(channel_state) == CHANNEL_STATE_SETTLED:

        our_state = channel_state.our_state
        partner_state = channel_state.partner_state

        # partner is the address of the sender
        if state_change.sender == our_state.address:
            our_state.onchain_locksroot = Locksroot(LOCKSROOT_OF_NO_LOCKS)
        elif state_change.sender == partner_state.address:
            partner_state.onchain_locksroot = Locksroot(LOCKSROOT_OF_NO_LOCKS)

        # only clear the channel state once all unlocks have been done
        no_unlock_left_to_do = our_state.onchain_locksroot == Locksroot(
            LOCKSROOT_OF_NO_LOCKS
        ) and partner_state.onchain_locksroot == Locksroot(LOCKSROOT_OF_NO_LOCKS)

        if no_unlock_left_to_do:
            new_channel_state = None

    return TransitionResult(new_channel_state, events)


def state_transition(
    channel_state: NettingChannelState,
    state_change: StateChange,
    block_number: BlockNumber,
    block_hash: BlockHash,
    pseudo_random_generator: random.Random,
) -> TransitionResult[Optional[NettingChannelState]]:  # pragma: no unittest
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    events: List[Event] = list()
    iteration: TransitionResult[Optional[NettingChannelState]] = TransitionResult(
        channel_state, events
    )

    if type(state_change) == Block:
        assert isinstance(state_change, Block), MYPY_ANNOTATION
        iteration = handle_block(
            channel_state, state_change, block_number, pseudo_random_generator
        )
    elif type(state_change) == ActionChannelClose:
        assert isinstance(state_change, ActionChannelClose), MYPY_ANNOTATION
        iteration = handle_action_close(
            channel_state=channel_state,
            close=state_change,
            block_number=block_number,
            block_hash=block_hash,
        )
    elif type(state_change) == ActionChannelUpdateFee:
        assert isinstance(state_change, ActionChannelUpdateFee), MYPY_ANNOTATION
        iteration = handle_action_update_fee(channel_state=channel_state, update_fee=state_change)
    elif type(state_change) == ActionChannelWithdraw:
        assert isinstance(state_change, ActionChannelWithdraw), MYPY_ANNOTATION
        iteration = handle_action_withdraw(
            channel_state=channel_state,
            action_withdraw=state_change,
            pseudo_random_generator=pseudo_random_generator,
            block_number=block_number,
        )
    elif type(state_change) == ContractReceiveChannelClosed:
        assert isinstance(state_change, ContractReceiveChannelClosed), MYPY_ANNOTATION
        iteration = handle_channel_closed(channel_state, state_change)
    elif type(state_change) == ContractReceiveUpdateTransfer:
        assert isinstance(state_change, ContractReceiveUpdateTransfer), MYPY_ANNOTATION
        iteration = handle_channel_updated_transfer(channel_state, state_change, block_number)
    elif type(state_change) == ContractReceiveChannelSettled:
        assert isinstance(state_change, ContractReceiveChannelSettled), MYPY_ANNOTATION
        iteration = handle_channel_settled(channel_state, state_change)
    elif type(state_change) == ContractReceiveChannelNewBalance:
        assert isinstance(state_change, ContractReceiveChannelNewBalance), MYPY_ANNOTATION
        iteration = handle_channel_newbalance(channel_state, state_change, block_number)
    elif type(state_change) == ContractReceiveChannelBatchUnlock:
        assert isinstance(state_change, ContractReceiveChannelBatchUnlock), MYPY_ANNOTATION
        iteration = handle_channel_batch_unlock(channel_state, state_change)
    elif type(state_change) == ContractReceiveChannelWithdraw:
        assert isinstance(state_change, ContractReceiveChannelWithdraw), MYPY_ANNOTATION
        iteration = handle_channel_withdraw(channel_state=channel_state, state_change=state_change)
    elif type(state_change) == ReceiveWithdrawRequest:
        assert isinstance(state_change, ReceiveWithdrawRequest), MYPY_ANNOTATION
        iteration = handle_receive_withdraw_request(
            channel_state=channel_state, withdraw_request=state_change
        )
    elif type(state_change) == ReceiveWithdrawConfirmation:
        assert isinstance(state_change, ReceiveWithdrawConfirmation), MYPY_ANNOTATION
        iteration = handle_receive_withdraw_confirmation(
            channel_state=channel_state, withdraw=state_change, block_hash=block_hash
        )
    elif type(state_change) == ReceiveWithdrawExpired:
        assert isinstance(state_change, ReceiveWithdrawExpired), MYPY_ANNOTATION
        iteration = handle_receive_withdraw_expired(
            channel_state=channel_state, withdraw_expired=state_change, block_number=block_number
        )

    return iteration
