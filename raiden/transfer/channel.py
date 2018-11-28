# pylint: disable=too-many-lines
import heapq
import random

from eth_utils import encode_hex

from raiden.constants import EMPTY_HASH_KECCAK, MAXIMUM_PENDING_TRANSFERS, UINT256_MAX
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.transfer.architecture import Event, StateChange, TransitionResult
from raiden.transfer.balance_proof import pack_balance_proof
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedLockExpired,
    EventInvalidReceivedTransferRefund,
    EventInvalidReceivedUnlock,
    EventPaymentReceivedSuccess,
    EventPaymentSentFailed,
    EventTransferReceivedInvalidDirectTransfer,
    SendDirectTransfer,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.events import (
    CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    refund_from_sendmediated,
)
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    LockedTransferUnsignedState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveLockExpired,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.merkle_tree import LEAVES, compute_layers, compute_merkleproof_for, merkleroot
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    EMPTY_MERKLE_ROOT,
    EMPTY_MERKLE_TREE,
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    HashTimeLockState,
    MerkleTreeState,
    NettingChannelEndState,
    NettingChannelState,
    TransactionChannelNewBalance,
    TransactionExecutionStatus,
    TransactionOrder,
    UnlockPartialProofState,
    UnlockProofState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import (
    ActionChannelClose,
    ActionTransferDirect,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveUpdateTransfer,
    ReceiveTransferDirect,
    ReceiveUnlock,
)
from raiden.transfer.utils import hash_balance_data
from raiden.utils import pex, typing
from raiden.utils.signing import eth_recover

# This should be changed to `Union[str, MerkleTreeState]`
MerkletreeOrError = typing.Tuple[bool, typing.Optional[str], typing.Optional[typing.Any]]
EventsOrError = typing.Tuple[bool, typing.List[Event], typing.Any]
BalanceProofData = typing.Tuple[
    typing.Locksroot,
    typing.Nonce,
    typing.TokenAmount,
    typing.TokenAmount,
]
SendUnlockAndMerkleTree = typing.Tuple[SendBalanceProof, MerkleTreeState]


def is_lock_pending(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> bool:
    """True if the `secrethash` corresponds to a lock that is pending to be claimed
    and didn't expire.
    """
    return (
        secrethash in end_state.secrethashes_to_lockedlocks or
        secrethash in end_state.secrethashes_to_unlockedlocks or
        secrethash in end_state.secrethashes_to_onchain_unlockedlocks
    )


def is_deposit_confirmed(
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
) -> bool:
    if not channel_state.deposit_transaction_queue:
        return False

    return is_transaction_confirmed(
        channel_state.deposit_transaction_queue[0].block_number,
        block_number,
    )


def is_lock_locked(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> bool:
    """True if the `secrethash` is for a lock with an unknown secret."""
    return secrethash in end_state.secrethashes_to_lockedlocks


def is_lock_expired(
        end_state: NettingChannelEndState,
        lock: HashTimeLockState,
        block_number: typing.BlockNumber,
        lock_expiration_threshold: typing.BlockNumber,
) -> typing.SuccessOrError:
    """ Determine whether a lock has expired.

    The lock has expired if both:

        - The secret was not registered on-chain in time.
        - The current block exceeds lock's expiration + confirmation blocks.
    """

    secret_registered_on_chain = lock.secrethash in end_state.secrethashes_to_onchain_unlockedlocks
    if secret_registered_on_chain:
        return (False, 'lock has been unlocked on-chain')

    if block_number < lock_expiration_threshold:
        msg = (
            f'current block number ({block_number}) is not larger than '
            f'lock.expiration + confirmation blocks ({lock_expiration_threshold})'
        )
        return (False, msg)

    return (True, None)


def is_secret_known(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> bool:
    """True if the `secrethash` is for a lock with a known secret."""
    return (
        secrethash in end_state.secrethashes_to_unlockedlocks or
        secrethash in end_state.secrethashes_to_onchain_unlockedlocks
    )


def is_secret_known_offchain(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> bool:
    """True if the `secrethash` is for a lock with a known secret."""
    return secrethash in end_state.secrethashes_to_unlockedlocks


def is_secret_known_onchain(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> bool:
    """True if the `secrethash` is for a lock with a known secret."""
    return secrethash in end_state.secrethashes_to_onchain_unlockedlocks


def get_secret(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> typing.Optional[typing.Secret]:
    """Returns `secret` if the `secrethash` is for a lock with a known secret."""
    if is_secret_known(end_state, secrethash):
        partial_unlock_proof = end_state.secrethashes_to_unlockedlocks.get(secrethash)

        if partial_unlock_proof is None:
            partial_unlock_proof = end_state.secrethashes_to_onchain_unlockedlocks.get(secrethash)

        return partial_unlock_proof.secret

    return None


def is_transaction_confirmed(
        transaction_block_number: typing.BlockNumber,
        blockchain_block_number: typing.BlockNumber,
) -> bool:
    confirmation_block = transaction_block_number + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    return blockchain_block_number > confirmation_block


def is_balance_proof_safe_for_onchain_operations(
        balance_proof: BalanceProofSignedState,
) -> bool:
    """ Check if the balance proof would overflow onchain. """
    total_amount = balance_proof.transferred_amount + balance_proof.locked_amount
    return total_amount <= UINT256_MAX


def is_valid_amount(
        end_state: NettingChannelEndState,
        amount: typing.TokenAmount,
) -> bool:
    (
        _,
        _,
        current_transferred_amount,
        current_locked_amount,
    ) = get_current_balanceproof(end_state)

    transferred_amount_after_unlock = (
        current_transferred_amount +
        current_locked_amount +
        amount
    )

    return transferred_amount_after_unlock <= UINT256_MAX


def is_valid_signature(
        balance_proof: BalanceProofSignedState,
        sender_address: typing.Address,
) -> typing.SuccessOrError:
    balance_hash = hash_balance_data(
        balance_proof.transferred_amount,
        balance_proof.locked_amount,
        balance_proof.locksroot,
    )

    # The balance proof must be tied to a single channel instance, through the
    # chain_id, token_network_identifier, and channel_identifier, otherwise the
    # on-chain contract would be susceptible to replay attacks across channels.
    #
    # The balance proof must also authenticate the offchain balance (blinded in
    # the balance_hash field), and authenticate the rest of message data
    # (blinded in additional_hash).
    data_that_was_signed = pack_balance_proof(
        nonce=balance_proof.nonce,
        balance_hash=balance_hash,
        additional_hash=balance_proof.message_hash,
        channel_identifier=balance_proof.channel_identifier,
        token_network_identifier=balance_proof.token_network_identifier,
        chain_id=balance_proof.chain_id,
    )

    try:
        signer_address = eth_recover(
            data=data_that_was_signed,
            signature=balance_proof.signature,
        )
        # InvalidSignature is raised by eth_utils.eth_recover if signature
        # is not bytes or has the incorrect length
        #
        # ValueError is raised if the PublicKey instantiation failed, let it
        # propagate because it's a memory pressure problem.
        #
        # Exception is raised if the public key recovery failed.
    except Exception:  # pylint: disable=broad-except
        msg = 'Signature invalid, could not be recovered.'
        return (False, msg)

    is_correct_sender = sender_address == signer_address
    if is_correct_sender:
        return (True, None)

    msg = 'Signature was valid but the expected address does not match.'
    return (False, msg)


def is_balance_proof_usable_onchain(
        received_balance_proof: BalanceProofSignedState,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
) -> typing.SuccessOrError:
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

    is_valid_signature_, signature_msg = is_valid_signature(
        received_balance_proof,
        sender_state.address,
    )

    # TODO: Accept unlock messages if the node has not yet sent a transaction
    # with the balance proof to the blockchain, this will save one call to
    # unlock on-chain for the non-closing party.
    if get_status(channel_state) != CHANNEL_STATE_OPENED:
        # The channel must be opened, otherwise if receiver is the closer, the
        # balance proof cannot be used onchain.
        msg = f'The channel is already closed.'
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

    elif received_balance_proof.token_network_identifier != channel_state.token_network_identifier:
        # Informational message, the token_network_identifier **validated by
        # the signature** must match for the balance_proof to be valid.
        msg = (
            f"token_network_identifier does not match. "
            f"expected: {channel_state.token_network_identifier} "
            f"got: {received_balance_proof.token_network_identifier}."
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
            received_balance_proof.transferred_amount +
            received_balance_proof.locked_amount
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
            f'Nonce did not change sequentially, expected: {expected_nonce} '
            f'got: {received_balance_proof.nonce}.'
        )

        result = (False, msg)

    elif not is_valid_signature_:
        # The signature must be valid, otherwise the balance proof cannot be
        # used onchain.
        result = (False, signature_msg)

    else:
        result = (True, None)

    return result


def is_valid_directtransfer(
        direct_transfer: ReceiveTransferDirect,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
        receiver_state: NettingChannelEndState,
) -> typing.SuccessOrError:
    received_balance_proof = direct_transfer.balance_proof

    (
        current_locksroot,
        _,
        current_transferred_amount,
        current_locked_amount,
    ) = get_current_balanceproof(sender_state)

    distributable = get_distributable(sender_state, receiver_state)
    amount = received_balance_proof.transferred_amount - current_transferred_amount

    is_balance_proof_usable, invalid_balance_proof_msg = is_balance_proof_usable_onchain(
        received_balance_proof=received_balance_proof,
        channel_state=channel_state,
        sender_state=sender_state,
    )

    if not is_balance_proof_usable:
        msg = 'Invalid DirectTransfer message. {}'.format(invalid_balance_proof_msg)
        result = (False, msg)

    elif received_balance_proof.locksroot != current_locksroot:
        # Direct transfers do not use hash time lock, so it cannot change the
        # locksroot, otherwise a lock could be removed.
        msg = (
            "Invalid DirectTransfer message. "
            "Balance proof's locksroot changed, expected: {} got: {}."
        ).format(
            encode_hex(current_locksroot),
            encode_hex(received_balance_proof.locksroot),
        )

        result = (False, msg)

    elif received_balance_proof.transferred_amount <= current_transferred_amount:
        # Direct transfers must increase the transferred_amount, otherwise the
        # sender is trying to play the protocol and steal token.
        msg = (
            "Invalid DirectTransfer message. "
            "Balance proof's transferred_amount decreased, expected larger than: {} got: {}."
        ).format(
            current_transferred_amount,
            received_balance_proof.transferred_amount,
        )

        result = (False, msg)

    elif received_balance_proof.locked_amount != current_locked_amount:
        # Direct transfers must not change the locked_amount. Otherwise the
        # sender is trying to play the protocol and steal token.
        msg = (
            "Invalid DirectTransfer message. "
            "Balance proof's locked_amount is invalid, expected: {} got: {}."
        ).format(
            current_locked_amount,
            received_balance_proof.locked_amount,
        )

        result = (False, msg)

    elif amount > distributable:
        # Direct transfer are limited to the current available balance,
        # otherwise the sender is doing a trying to play the protocol and do a
        # double spend.
        msg = (
            'Invalid DirectTransfer message. '
            'Transfer amount larger than the available distributable, '
            'transfer amount: {} maximum distributable: {}'
        ).format(
            amount,
            distributable,
        )

        result = (False, msg)

    else:
        result = (True, None)

    return result


def is_valid_lockedtransfer(
        transfer_state: LockedTransferSignedState,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
        receiver_state: NettingChannelEndState,
) -> MerkletreeOrError:
    return valid_lockedtransfer_check(
        channel_state,
        sender_state,
        receiver_state,
        'LockedTransfer',
        transfer_state.balance_proof,
        transfer_state.lock,
    )


def is_valid_lock_expired(
        state_change: ReceiveLockExpired,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
        receiver_state: NettingChannelEndState,
        block_number: typing.BlockNumber,
) -> MerkletreeOrError:
    secrethash = state_change.secrethash
    received_balance_proof = state_change.balance_proof
    lock = channel_state.partner_state.secrethashes_to_lockedlocks.get(secrethash)

    # If the lock was not found in locked locks, this means that we've received
    # the secret for the locked transfer but we haven't unlocked it yet. Lock
    # expiry in this case could still happen which means that we have to make
    # sure that we check for "unclaimed" locks in our check.
    if not lock:
        lock = channel_state.partner_state.secrethashes_to_unlockedlocks.get(secrethash)

    lock_registered_on_chain = (
        secrethash in channel_state.our_state.secrethashes_to_onchain_unlockedlocks
    )

    if not lock:
        msg = (
            f'Invalid LockExpired message. '
            f'Lock with secrethash {pex(secrethash)} is not known.'
        )
        return (False, msg, None)

    current_balance_proof = get_current_balanceproof(sender_state)
    merkletree = compute_merkletree_without(sender_state.merkletree, lock.lockhash)

    _, _, current_transferred_amount, current_locked_amount = current_balance_proof
    expected_locked_amount = current_locked_amount - lock.amount

    is_balance_proof_usable, invalid_balance_proof_msg = is_balance_proof_usable_onchain(
        received_balance_proof=received_balance_proof,
        channel_state=channel_state,
        sender_state=sender_state,
    )

    result: MerkletreeOrError = (False, None, None)

    if not is_balance_proof_usable:
        msg = 'Invalid LockExpired message. {}'.format(invalid_balance_proof_msg)
        result = (False, msg, None)

    elif merkletree is None:
        msg = 'Invalid LockExpired message. Same lockhash handled twice.'
        result = (False, msg, None)

    elif lock_registered_on_chain:
        msg = 'Invalid LockExpired mesage. Lock was unlocked on-chain.'
        result = (False, msg, None)

    else:
        locksroot_without_lock = merkleroot(merkletree)
        has_expired, lock_expired_message = is_lock_expired(
            end_state=receiver_state,
            lock=lock,
            block_number=block_number,
            lock_expiration_threshold=typing.BlockNumber(
                lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
            ),
        )

        if not has_expired:
            msg = f'Invalid LockExpired message. {lock_expired_message}'
            result = (False, msg, None)

        elif received_balance_proof.locksroot != locksroot_without_lock:
            # The locksroot must be updated, and the expired lock must be *removed*
            msg = (
                "Invalid LockExpired message. "
                "Balance proof's locksroot didn't match, expected: {} got: {}."
            ).format(
                encode_hex(locksroot_without_lock),
                encode_hex(received_balance_proof.locksroot),
            )

            result = (False, msg, None)

        elif received_balance_proof.transferred_amount != current_transferred_amount:
            # Given an expired lock, transferred amount should stay the same
            msg = (
                'Invalid LockExpired message. '
                "Balance proof's transferred_amount changed, expected: {} got: {}."
            ).format(
                current_transferred_amount,
                received_balance_proof.transferred_amount,
            )

            result = (False, msg, None)

        elif received_balance_proof.locked_amount != expected_locked_amount:
            # locked amount should be the same found inside the balance proof
            msg = (
                'Invalid LockExpired message. '
                "Balance proof's locked_amount is invalid, expected: {} got: {}."
            ).format(
                expected_locked_amount,
                received_balance_proof.locked_amount,
            )

            result = (False, msg, None)

        else:
            result = (True, None, merkletree)

    return result


def valid_lockedtransfer_check(
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
        receiver_state: NettingChannelEndState,
        message_name: str,
        received_balance_proof: BalanceProofSignedState,
        lock: HashTimeLockState,
) -> MerkletreeOrError:

    current_balance_proof = get_current_balanceproof(sender_state)
    merkletree = compute_merkletree_with(sender_state.merkletree, lock.lockhash)

    _, _, current_transferred_amount, current_locked_amount = current_balance_proof
    distributable = get_distributable(sender_state, receiver_state)
    expected_locked_amount = current_locked_amount + lock.amount

    is_balance_proof_usable, invalid_balance_proof_msg = is_balance_proof_usable_onchain(
        received_balance_proof=received_balance_proof,
        channel_state=channel_state,
        sender_state=sender_state,
    )

    result: MerkletreeOrError = (False, None, None)

    if not is_balance_proof_usable:
        msg = f'Invalid {message_name} message. {invalid_balance_proof_msg}'
        result = (False, msg, None)

    elif merkletree is None:
        msg = 'Invalid {} message. Same lockhash handled twice.'.format(message_name)
        result = (False, msg, None)

    elif _merkletree_width(merkletree) > MAXIMUM_PENDING_TRANSFERS:
        msg = (
            f'Invalid {message_name} message. Adding the transfer would exceed the allowed '
            f'limit of {MAXIMUM_PENDING_TRANSFERS} pending transfers per channel.'
        )
        result = (False, msg, None)

    else:
        locksroot_with_lock = merkleroot(merkletree)

        if received_balance_proof.locksroot != locksroot_with_lock:
            # The locksroot must be updated to include the new lock
            msg = (
                'Invalid {} message. '
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
                'Invalid {} message. '
                "Balance proof's transferred_amount changed, expected: {} got: {}."
            ).format(
                message_name,
                current_transferred_amount,
                received_balance_proof.transferred_amount,
            )

            result = (False, msg, None)

        elif received_balance_proof.locked_amount != expected_locked_amount:
            # Mediated transfers must increase the locked_amount by lock.amount
            msg = (
                'Invalid {} message. '
                "Balance proof's locked_amount is invalid, expected: {} got: {}."
            ).format(
                message_name,
                expected_locked_amount,
                received_balance_proof.locked_amount,
            )

            result = (False, msg, None)

        # the locked amount is limited to the current available balance, otherwise
        # the sender is attempting to game the protocol and do a double spend
        elif lock.amount > distributable:
            msg = (
                'Invalid {} message. '
                'Lock amount larger than the available distributable, '
                'lock amount: {} maximum distributable: {}'
            ).format(
                message_name,
                lock.amount,
                distributable,
            )

            result = (False, msg, None)

        # if the message contains the keccak of the empty hash it will never be
        # usable onchain https://github.com/raiden-network/raiden/issues/3091
        elif lock.secrethash == EMPTY_HASH_KECCAK:
            msg = (
                f'Invalid {message_name} message. '
                'The secrethash is the keccak of 0x0 and will not be usable onchain'
            )
            result = (False, msg, None)

        else:
            result = (True, None, merkletree)

    return result


def refund_transfer_matches_received(
        refund_transfer: LockedTransferSignedState,
        received_transfer: LockedTransferUnsignedState,
):
    refund_transfer_sender = refund_transfer.balance_proof.sender
    # Ignore a refund from the target
    if refund_transfer_sender == received_transfer.target:
        return False

    return (
        received_transfer.payment_identifier == refund_transfer.payment_identifier and
        received_transfer.lock.amount == refund_transfer.lock.amount and
        received_transfer.lock.secrethash == refund_transfer.lock.secrethash and
        received_transfer.target == refund_transfer.target and
        received_transfer.lock.expiration == refund_transfer.lock.expiration and

        # The refund transfer is not tied to the other direction of the same
        # channel, it may reach this node through a different route depending
        # on the path finding strategy
        # original_receiver == refund_transfer_sender and
        received_transfer.token == refund_transfer.token
    )


def is_valid_refund(
        refund: ReceiveTransferRefund,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
        receiver_state: NettingChannelEndState,
        received_transfer: LockedTransferUnsignedState,
) -> MerkletreeOrError:
    is_valid_locked_transfer, msg, merkletree = valid_lockedtransfer_check(
        channel_state,
        sender_state,
        receiver_state,
        'RefundTransfer',
        refund.transfer.balance_proof,
        refund.transfer.lock,
    )

    if not is_valid_locked_transfer:
        return False, msg, None

    if not refund_transfer_matches_received(refund.transfer, received_transfer):
        return False, 'Refund transfer did not match the received transfer', None

    return True, '', merkletree


def is_valid_unlock(
        unlock: ReceiveUnlock,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
) -> MerkletreeOrError:
    received_balance_proof = unlock.balance_proof
    current_balance_proof = get_current_balanceproof(sender_state)

    lock = get_lock(sender_state, unlock.secrethash)

    if lock is None:
        msg = 'Invalid Unlock message. There is no corresponding lock for {}'.format(
            encode_hex(unlock.secrethash),
        )

        return (False, msg, None)

    merkletree = compute_merkletree_without(sender_state.merkletree, lock.lockhash)
    locksroot_without_lock = merkleroot(merkletree)

    _, _, current_transferred_amount, current_locked_amount = current_balance_proof

    expected_transferred_amount = (
        current_transferred_amount +
        typing.TokenAmount(lock.amount)
    )
    expected_locked_amount = current_locked_amount - lock.amount

    is_balance_proof_usable, invalid_balance_proof_msg = is_balance_proof_usable_onchain(
        received_balance_proof=received_balance_proof,
        channel_state=channel_state,
        sender_state=sender_state,
    )

    result: MerkletreeOrError = (False, None, None)

    if not is_balance_proof_usable:
        msg = 'Invalid Unlock message. {}'.format(invalid_balance_proof_msg)
        result = (False, msg, None)

    elif received_balance_proof.locksroot != locksroot_without_lock:
        # Secret messages remove a known lock, the new locksroot must have only
        # that lock removed, otherwise the sender may be trying to remove
        # additional locks.
        msg = (
            'Invalid Unlock message. '
            "Balance proof's locksroot didn't match, expected: {} got: {}."
        ).format(
            encode_hex(locksroot_without_lock),
            encode_hex(received_balance_proof.locksroot),
        )

        result = (False, msg, None)

    elif received_balance_proof.transferred_amount != expected_transferred_amount:
        # Secret messages must increase the transferred_amount by lock amount,
        # otherwise the sender is trying to play the protocol and steal token.
        msg = (
            "Invalid Unlock message. "
            "Balance proof's wrong transferred_amount, expected: {} got: {}."
        ).format(
            expected_transferred_amount,
            received_balance_proof.transferred_amount,
        )

        result = (False, msg, None)

    elif received_balance_proof.locked_amount != expected_locked_amount:
        # Secret messages must increase the transferred_amount by lock amount,
        # otherwise the sender is trying to play the protocol and steal token.
        msg = (
            "Invalid Unlock message. "
            "Balance proof's wrong locked_amount, expected: {} got: {}."
        ).format(
            expected_locked_amount,
            received_balance_proof.locked_amount,
        )

        result = (False, msg, None)

    else:
        result = (True, None, merkletree)

    return result


def get_amount_locked(end_state: NettingChannelEndState) -> typing.TokenAmount:
    total_pending = sum(
        lock.amount
        for lock in end_state.secrethashes_to_lockedlocks.values()
    )

    total_unclaimed = sum(
        unlock.lock.amount
        for unlock in end_state.secrethashes_to_unlockedlocks.values()
    )

    total_unclaimed_onchain = sum(
        unlock.lock.amount
        for unlock in end_state.secrethashes_to_onchain_unlockedlocks.values()
    )

    return total_pending + total_unclaimed + total_unclaimed_onchain


def get_balance(
        sender: NettingChannelEndState,
        receiver: NettingChannelEndState,
) -> typing.Balance:
    sender_transferred_amount = 0
    receiver_transferred_amount = 0

    if sender.balance_proof:
        sender_transferred_amount = sender.balance_proof.transferred_amount

    if receiver.balance_proof:
        receiver_transferred_amount = receiver.balance_proof.transferred_amount

    return (
        sender.contract_balance -
        sender_transferred_amount +
        receiver_transferred_amount
    )


def get_current_balanceproof(end_state: NettingChannelEndState) -> BalanceProofData:
    balance_proof = end_state.balance_proof

    if balance_proof:
        locksroot = balance_proof.locksroot
        nonce = balance_proof.nonce
        transferred_amount = balance_proof.transferred_amount
        locked_amount = get_amount_locked(end_state)
    else:
        locksroot = EMPTY_MERKLE_ROOT
        nonce = 0
        transferred_amount: typing.TokenAmount = 0
        locked_amount: typing.TokenAmount = 0

    return (locksroot, nonce, transferred_amount, locked_amount)


def get_distributable(
        sender: NettingChannelEndState,
        receiver: NettingChannelEndState,
) -> typing.TokenAmount:
    """Return the amount of tokens that can be used by the `sender`.

    The returned value is limited to a UINT256, since that is the representation
    used in the smart contracts and we cannot use a larger value. The limit is
    enforced on transferred_amount + locked_amount to avoid overflows. This is
    an additional security check.
    """
    _, _, transferred_amount, locked_amount = get_current_balanceproof(sender)

    distributable = get_balance(sender, receiver) - get_amount_locked(sender)

    overflow_limit = max(
        UINT256_MAX - transferred_amount - locked_amount,
        0,
    )

    return min(overflow_limit, distributable)


def get_batch_unlock(
        end_state: NettingChannelEndState,
) -> typing.Optional[typing.MerkleTreeLeaves]:
    """ Unlock proof for an entire merkle tree of pending locks

    The unlock proof contains all the merkle tree data, tightly packed, needed by the token
    network contract to verify the secret expiry and calculate the token amounts to transfer.
    """

    if len(end_state.merkletree.layers[LEAVES]) == 0:  # pylint: disable=len-as-condition
        return None

    lockhashes_to_locks = dict()
    lockhashes_to_locks.update({
        lock.lockhash: lock
        for secrethash, lock in end_state.secrethashes_to_lockedlocks.items()
    })
    lockhashes_to_locks.update({
        proof.lock.lockhash: proof.lock
        for secrethash, proof in end_state.secrethashes_to_unlockedlocks.items()
    })
    lockhashes_to_locks.update({
        proof.lock.lockhash: proof.lock
        for secrethash, proof in end_state.secrethashes_to_onchain_unlockedlocks.items()
    })

    ordered_locks = [
        lockhashes_to_locks[lockhash]
        for lockhash in end_state.merkletree.layers[LEAVES]
    ]

    return ordered_locks


def get_lock(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> HashTimeLockState:
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


def get_next_nonce(end_state: NettingChannelEndState) -> typing.Nonce:
    if end_state.balance_proof:
        return end_state.balance_proof.nonce + 1

    # 0 must not be used since in the netting contract it represents null.
    return 1


def _merkletree_width(merkletree: MerkleTreeState) -> int:
    return len(merkletree.layers[LEAVES])


def get_number_of_pending_transfers(channel_end_state: NettingChannelEndState) -> int:
    return _merkletree_width(channel_end_state.merkletree)


def get_status(channel_state):
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


def _del_unclaimed_lock(end_state: NettingChannelEndState, secrethash: typing.SecretHash):
    if secrethash in end_state.secrethashes_to_lockedlocks:
        del end_state.secrethashes_to_lockedlocks[secrethash]

    if secrethash in end_state.secrethashes_to_unlockedlocks:
        del end_state.secrethashes_to_unlockedlocks[secrethash]


def _del_lock(end_state: NettingChannelEndState, secrethash: typing.SecretHash) -> None:
    """Removes the lock from the indexing structures.

    Note:
        This won't change the merkletree!
    """
    assert is_lock_pending(end_state, secrethash)

    _del_unclaimed_lock(end_state, secrethash)

    if secrethash in end_state.secrethashes_to_onchain_unlockedlocks:
        del end_state.secrethashes_to_onchain_unlockedlocks[secrethash]


def set_closed(
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
) -> None:
    if not channel_state.close_transaction:
        channel_state.close_transaction = TransactionExecutionStatus(
            None,
            block_number,
            TransactionExecutionStatus.SUCCESS,
        )

    elif not channel_state.close_transaction.finished_block_number:
        channel_state.close_transaction.finished_block_number = block_number
        channel_state.close_transaction.result = TransactionExecutionStatus.SUCCESS


def set_settled(
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
) -> None:
    if not channel_state.settle_transaction:
        channel_state.settle_transaction = TransactionExecutionStatus(
            None,
            block_number,
            TransactionExecutionStatus.SUCCESS,
        )

    elif not channel_state.settle_transaction.finished_block_number:
        channel_state.settle_transaction.finished_block_number = block_number
        channel_state.settle_transaction.result = TransactionExecutionStatus.SUCCESS


def update_contract_balance(
        end_state: NettingChannelEndState,
        contract_balance: typing.Balance,
) -> None:
    if contract_balance > end_state.contract_balance:
        end_state.contract_balance = contract_balance


def compute_proof_for_lock(
        end_state: NettingChannelEndState,
        secret: typing.Secret,
        lock: HashTimeLockState,
) -> UnlockProofState:
    # forcing bytes because ethereum.abi doesn't work with bytearray
    merkle_proof = compute_merkleproof_for(end_state.merkletree, lock.lockhash)

    return UnlockProofState(
        merkle_proof,
        lock.encoded,
        secret,
    )


def compute_merkletree_with(
        merkletree: MerkleTreeState,
        lockhash: typing.LockHash,
) -> typing.Optional[MerkleTreeState]:
    """Register the given lockhash with the existing merkle tree."""
    # Use None to inform the caller the lockshash is already known
    result = None

    leaves = merkletree.layers[LEAVES]
    if lockhash not in leaves:
        leaves = list(leaves)
        leaves.append(lockhash)
        result = MerkleTreeState(compute_layers(leaves))

    return result


def compute_merkletree_without(
        merkletree: MerkleTreeState,
        lockhash: typing.LockHash,
) -> MerkleTreeState:
    # Use None to inform the caller the lockshash is unknown
    result = None

    leaves = merkletree.layers[LEAVES]
    if lockhash in leaves:
        leaves = list(leaves)
        leaves.remove(lockhash)

        if leaves:
            result = MerkleTreeState(compute_layers(leaves))
        else:
            result = EMPTY_MERKLE_TREE

    return result


def create_senddirecttransfer(
        channel_state: NettingChannelState,
        amount: typing.PaymentAmount,
        message_identifier: typing.MessageID,
        payment_identifier: typing.PaymentID,
) -> SendDirectTransfer:
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state

    msg = 'caller must make sure there is enough balance'
    assert amount <= get_distributable(our_state, partner_state), msg

    msg = 'caller must make sure the channel is open'
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    our_balance_proof = channel_state.our_state.balance_proof

    if our_balance_proof:
        transferred_amount = amount + our_balance_proof.transferred_amount
        locksroot = our_balance_proof.locksroot
    else:
        transferred_amount = amount
        locksroot = EMPTY_MERKLE_ROOT

    msg = 'caller must make sure the result wont overflow'
    assert transferred_amount <= UINT256_MAX, msg

    nonce = get_next_nonce(our_state)
    recipient = partner_state.address
    locked_amount = get_amount_locked(our_state)

    balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        token_network_identifier=channel_state.token_network_identifier,
        channel_identifier=channel_state.identifier,
        chain_id=channel_state.chain_id,
    )

    direct_transfer = SendDirectTransfer(
        recipient=recipient,
        channel_identifier=channel_state.identifier,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        balance_proof=balance_proof,
        token_address=channel_state.token_address,
    )

    return direct_transfer


def create_sendlockedtransfer(
        channel_state: NettingChannelState,
        initiator: typing.InitiatorAddress,
        target: typing.TargetAddress,
        amount: typing.PaymentAmount,
        message_identifier: typing.MessageID,
        payment_identifier: typing.PaymentID,
        expiration: typing.BlockExpiration,
        secrethash: typing.SecretHash,
) -> typing.Tuple[SendLockedTransfer, typing.Optional[MerkleTreeState]]:
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state
    our_balance_proof = our_state.balance_proof

    msg = 'caller must make sure there is enough balance'
    assert amount <= get_distributable(our_state, partner_state), msg

    msg = 'caller must make sure the channel is open'
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    lock = HashTimeLockState(
        amount,
        expiration,
        secrethash,
    )

    merkletree = compute_merkletree_with(
        channel_state.our_state.merkletree,
        lock.lockhash,
    )
    # The caller must ensure the same lock is not being used twice
    assert merkletree, 'lock is already registered'

    locksroot = merkleroot(merkletree)

    if our_balance_proof:
        transferred_amount = our_balance_proof.transferred_amount
    else:
        transferred_amount = 0

    msg = 'caller must make sure the result wont overflow'
    assert transferred_amount + amount <= UINT256_MAX, msg

    token = channel_state.token_address
    nonce = get_next_nonce(channel_state.our_state)
    recipient = channel_state.partner_state.address
    locked_amount = get_amount_locked(our_state) + amount  # the new lock is not registered yet

    balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        token_network_identifier=channel_state.token_network_identifier,
        channel_identifier=channel_state.identifier,
        chain_id=channel_state.chain_id,
    )

    locked_transfer = LockedTransferUnsignedState(
        payment_identifier,
        token,
        balance_proof,
        lock,
        typing.Address(initiator),
        typing.Address(target),
    )

    lockedtransfer = SendLockedTransfer(
        recipient=recipient,
        channel_identifier=channel_state.identifier,
        message_identifier=message_identifier,
        transfer=locked_transfer,
    )

    return lockedtransfer, merkletree


def create_unlock(
        channel_state: NettingChannelState,
        message_identifier: typing.MessageID,
        payment_identifier: typing.PaymentID,
        secret: typing.Secret,
        lock: HashTimeLockState,
) -> SendUnlockAndMerkleTree:
    our_state = channel_state.our_state

    msg = 'caller must make sure the lock is known'
    assert is_lock_pending(our_state, lock.secrethash), msg

    msg = 'caller must make sure the channel is open'
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    our_balance_proof = our_state.balance_proof
    if our_balance_proof:
        transferred_amount = lock.amount + our_balance_proof.transferred_amount
    else:
        transferred_amount = lock.amount

    merkletree = compute_merkletree_without(
        our_state.merkletree,
        lock.lockhash,
    )
    locksroot = merkleroot(merkletree)

    token_address = channel_state.token_address
    nonce = get_next_nonce(our_state)
    recipient = channel_state.partner_state.address
    locked_amount = get_amount_locked(our_state) - lock.amount  # the lock is still registered

    balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        token_network_identifier=channel_state.token_network_identifier,
        channel_identifier=channel_state.identifier,
        chain_id=channel_state.chain_id,
    )

    unlock_lock = SendBalanceProof(
        recipient=recipient,
        channel_identifier=channel_state.identifier,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        token_address=token_address,
        secret=secret,
        balance_proof=balance_proof,
    )

    return unlock_lock, merkletree


def send_directtransfer(
        channel_state: NettingChannelState,
        amount: typing.PaymentAmount,
        message_identifier: typing.MessageID,
        payment_identifier: typing.PaymentID,
) -> SendDirectTransfer:
    direct_transfer = create_senddirecttransfer(
        channel_state,
        amount,
        message_identifier,
        payment_identifier,
    )

    channel_state.our_state.balance_proof = direct_transfer.balance_proof

    return direct_transfer


def send_lockedtransfer(
        channel_state: NettingChannelState,
        initiator: typing.InitiatorAddress,
        target: typing.TargetAddress,
        amount: typing.PaymentAmount,
        message_identifier: typing.MessageID,
        payment_identifier: typing.PaymentID,
        expiration: typing.BlockExpiration,
        secrethash: typing.SecretHash,
) -> SendLockedTransfer:
    send_locked_transfer_event, merkletree = create_sendlockedtransfer(
        channel_state,
        initiator,
        target,
        amount,
        message_identifier,
        payment_identifier,
        expiration,
        secrethash,
    )

    transfer = send_locked_transfer_event.transfer
    lock = transfer.lock
    channel_state.our_state.balance_proof = transfer.balance_proof
    channel_state.our_state.merkletree = merkletree
    channel_state.our_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

    return send_locked_transfer_event


def send_refundtransfer(
        channel_state: NettingChannelState,
        initiator: typing.InitiatorAddress,
        target: typing.TargetAddress,
        amount: typing.PaymentAmount,
        message_identifier: typing.MessageID,
        payment_identifier: typing.PaymentID,
        expiration: typing.BlockExpiration,
        secrethash: typing.SecretHash,
) -> SendRefundTransfer:
    msg = 'Refunds are only valid for *known and pending* transfers'
    assert secrethash in channel_state.partner_state.secrethashes_to_lockedlocks, msg

    send_mediated_transfer, merkletree = create_sendlockedtransfer(
        channel_state,
        initiator,
        target,
        amount,
        message_identifier,
        payment_identifier,
        expiration,
        secrethash,
    )

    mediated_transfer = send_mediated_transfer.transfer
    lock = mediated_transfer.lock

    channel_state.our_state.balance_proof = mediated_transfer.balance_proof
    channel_state.our_state.merkletree = merkletree
    channel_state.our_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

    refund_transfer = refund_from_sendmediated(send_mediated_transfer)
    return refund_transfer


def send_unlock(
        channel_state: NettingChannelState,
        message_identifier: typing.MessageID,
        payment_identifier: typing.PaymentID,
        secret: typing.Secret,
        secrethash: typing.SecretHash,
) -> SendBalanceProof:
    lock = get_lock(channel_state.our_state, secrethash)
    assert lock

    unlock, merkletree = create_unlock(
        channel_state,
        message_identifier,
        payment_identifier,
        secret,
        lock,
    )

    channel_state.our_state.balance_proof = unlock.balance_proof
    channel_state.our_state.merkletree = merkletree

    _del_lock(channel_state.our_state, lock.secrethash)

    return unlock


def events_for_close(
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
) -> typing.List[Event]:
    events = list()

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED:
        channel_state.close_transaction = TransactionExecutionStatus(
            block_number,
            None,
            None,
        )

        close_event = ContractSendChannelClose(
            channel_state.identifier,
            channel_state.token_address,
            channel_state.token_network_identifier,
            channel_state.partner_state.balance_proof,
        )

        events.append(close_event)

    return events


def create_sendexpiredlock(
        sender_end_state: NettingChannelEndState,
        locked_lock: HashTimeLockState,
        pseudo_random_generator: random.Random,
        chain_id: typing.ChainID,
        token_network_identifier: typing.TokenNetworkID,
        channel_identifier: typing.ChannelID,
        recipient: typing.Address,
) -> typing.Tuple[typing.Optional[SendLockExpired], typing.Optional[MerkleTreeState]]:
    nonce = get_next_nonce(sender_end_state)
    locked_amount = get_amount_locked(sender_end_state)
    balance_proof = sender_end_state.balance_proof
    updated_locked_amount = locked_amount - locked_lock.amount
    transferred_amount = balance_proof.transferred_amount

    merkletree = compute_merkletree_without(sender_end_state.merkletree, locked_lock.lockhash)

    if not merkletree:
        return None, None

    locksroot = merkleroot(merkletree)

    balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=updated_locked_amount,
        locksroot=locksroot,
        token_network_identifier=token_network_identifier,
        channel_identifier=channel_identifier,
        chain_id=chain_id,
    )

    send_lock_expired = SendLockExpired(
        recipient=recipient,
        message_identifier=message_identifier_from_prng(pseudo_random_generator),
        balance_proof=balance_proof,
        secrethash=locked_lock.secrethash,
    )

    return send_lock_expired, merkletree


def events_for_expired_lock(
        channel_state: NettingChannelState,
        locked_lock: HashTimeLockState,
        pseudo_random_generator: random.Random,
) -> typing.List[SendLockExpired]:
    send_lock_expired, merkletree = create_sendexpiredlock(
        sender_end_state=channel_state.our_state,
        locked_lock=locked_lock,
        pseudo_random_generator=pseudo_random_generator,
        chain_id=channel_state.chain_id,
        token_network_identifier=channel_state.token_network_identifier,
        channel_identifier=channel_state.identifier,
        recipient=channel_state.partner_state.address,
    )

    if send_lock_expired:
        channel_state.our_state.merkletree = merkletree
        channel_state.our_state.balance_proof = send_lock_expired.balance_proof

        _del_unclaimed_lock(channel_state.our_state, locked_lock.secrethash)

        return [send_lock_expired]

    return []


def register_secret_endstate(
        end_state: NettingChannelEndState,
        secret: typing.Secret,
        secrethash: typing.SecretHash,
) -> None:
    if is_lock_locked(end_state, secrethash):
        pending_lock = end_state.secrethashes_to_lockedlocks[secrethash]
        del end_state.secrethashes_to_lockedlocks[secrethash]

        end_state.secrethashes_to_unlockedlocks[secrethash] = UnlockPartialProofState(
            pending_lock,
            secret,
        )


def register_onchain_secret_endstate(
        end_state: NettingChannelEndState,
        secret: typing.Secret,
        secrethash: typing.SecretHash,
        secret_reveal_block_number: typing.BlockNumber,
        delete_lock: bool = True,
) -> None:
    # the lock might be in end_state.secrethashes_to_lockedlocks or
    # end_state.secrethashes_to_unlockedlocks
    # It should be removed from both and moved into secrethashes_to_onchain_unlockedlocks
    pending_lock = None

    if is_lock_locked(end_state, secrethash):
        pending_lock: HashTimeLockState = end_state.secrethashes_to_lockedlocks[secrethash]

    if secrethash in end_state.secrethashes_to_unlockedlocks:
        pending_lock: HashTimeLockState = end_state.secrethashes_to_unlockedlocks[secrethash].lock

    if pending_lock:
        # If pending lock is still locked or unlocked but unclaimed
        # And has expired before the on-chain secret reveal was mined,
        # Then we simply reject on-chain secret reveal
        if pending_lock.expiration < secret_reveal_block_number:
            return

        if delete_lock:
            _del_lock(end_state, secrethash)

        end_state.secrethashes_to_onchain_unlockedlocks[secrethash] = UnlockPartialProofState(
            pending_lock,
            secret,
        )


def register_offchain_secret(
        channel_state: NettingChannelState,
        secret: typing.Secret,
        secrethash: typing.SecretHash,
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
        secret: typing.Secret,
        secrethash: typing.SecretHash,
        secret_reveal_block_number: typing.BlockNumber,
        delete_lock: bool = True,
) -> None:
    """This will register the onchain secret and set the lock to the unlocked stated.

    Even though the lock is unlocked it is *not* claimed. The capacity will
    increase once the next balance proof is received.
    """
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state

    register_onchain_secret_endstate(
        our_state,
        secret,
        secrethash,
        secret_reveal_block_number,
        delete_lock,
    )
    register_onchain_secret_endstate(
        partner_state,
        secret,
        secrethash,
        secret_reveal_block_number,
        delete_lock,
    )


def handle_send_directtransfer(
        channel_state: NettingChannelState,
        state_change: ActionTransferDirect,
        pseudo_random_generator: typing.Any,
) -> TransitionResult:
    events: typing.List[Event] = list()

    amount = state_change.amount
    payment_identifier = state_change.payment_identifier
    target_address = typing.TargetAddress(state_change.receiver_address)
    distributable_amount = get_distributable(channel_state.our_state, channel_state.partner_state)

    (
        _,
        _,
        current_transferred_amount,
        current_locked_amount,
    ) = get_current_balanceproof(channel_state.our_state)

    transferred_amount_after_unlock = (
        current_transferred_amount +
        amount +
        current_locked_amount
    )

    is_open = get_status(channel_state) == CHANNEL_STATE_OPENED
    is_valid = (
        amount > 0 and
        transferred_amount_after_unlock < UINT256_MAX
    )
    can_pay = amount <= distributable_amount

    if is_open and is_valid and can_pay:
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        direct_transfer = send_directtransfer(
            channel_state,
            amount,
            message_identifier,
            payment_identifier,
        )
        events.append(direct_transfer)
    else:
        if not is_open:
            failure = EventPaymentSentFailed(
                payment_network_identifier=channel_state.payment_network_identifier,
                token_network_identifier=channel_state.token_network_identifier,
                identifier=payment_identifier,
                target=target_address,
                reason='Channel is not opened',
            )
            events.append(failure)

        elif not is_valid:
            msg = 'Payment amount is invalid. Transfer: {}'.format(amount)
            failure = EventPaymentSentFailed(
                payment_network_identifier=channel_state.payment_network_identifier,
                token_network_identifier=channel_state.token_network_identifier,
                identifier=payment_identifier,
                target=target_address,
                reason=msg,
            )
            events.append(failure)

        elif not can_pay:
            msg = (
                'Payment amount exceeds the available capacity. '
                'Capacity: {}, Transfer: {}'
            ).format(
                distributable_amount,
                amount,
            )

            failure = EventPaymentSentFailed(
                payment_network_identifier=channel_state.payment_network_identifier,
                token_network_identifier=channel_state.token_network_identifier,
                identifier=payment_identifier,
                target=target_address,
                reason=msg,
            )
            events.append(failure)

    return TransitionResult(channel_state, events)


def handle_action_close(
        channel_state: NettingChannelState,
        close: ActionChannelClose,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    msg = 'caller must make sure the ids match'
    assert channel_state.identifier == close.channel_identifier, msg

    events = events_for_close(channel_state, block_number)
    return TransitionResult(channel_state, events)


def handle_receive_directtransfer(
        channel_state: NettingChannelState,
        direct_transfer: ReceiveTransferDirect,
) -> TransitionResult:
    is_valid, msg = is_valid_directtransfer(
        direct_transfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )

    if is_valid:
        (
            _,
            _,
            previous_transferred_amount,
            _,
        ) = get_current_balanceproof(channel_state.partner_state)

        new_transferred_amount = direct_transfer.balance_proof.transferred_amount
        transfer_amount = new_transferred_amount - previous_transferred_amount

        channel_state.partner_state.balance_proof = direct_transfer.balance_proof
        payment_received_success = EventPaymentReceivedSuccess(
            payment_network_identifier=channel_state.payment_network_identifier,
            token_network_identifier=channel_state.token_network_identifier,
            identifier=direct_transfer.payment_identifier,
            amount=transfer_amount,
            initiator=typing.InitiatorAddress(channel_state.partner_state.address),
        )

        send_processed = SendProcessed(
            recipient=direct_transfer.balance_proof.sender,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=direct_transfer.message_identifier,
        )
        events = [payment_received_success, send_processed]
    else:
        transfer_invalid_event = EventTransferReceivedInvalidDirectTransfer(
            direct_transfer.payment_identifier,
            reason=msg,
        )
        events = [transfer_invalid_event]

    return TransitionResult(channel_state, events)


def handle_refundtransfer(
        received_transfer: LockedTransferUnsignedState,
        channel_state: NettingChannelState,
        refund: ReceiveTransferRefund,
):
    is_valid, msg, merkletree = is_valid_refund(
        refund=refund,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
        receiver_state=channel_state.our_state,
        received_transfer=received_transfer,
    )
    if is_valid:
        channel_state.partner_state.balance_proof = refund.transfer.balance_proof
        channel_state.partner_state.merkletree = merkletree

        lock = refund.transfer.lock
        channel_state.partner_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

        send_processed = SendProcessed(
            recipient=refund.transfer.balance_proof.sender,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=refund.transfer.message_identifier,
        )
        events = [send_processed]
    else:
        invalid_refund = EventInvalidReceivedTransferRefund(
            payment_identifier=received_transfer.payment_identifier,
            reason=msg,
        )
        events = [invalid_refund]

    return is_valid, events, msg


def handle_receive_lock_expired(
        channel_state: NettingChannelState,
        state_change: ReceiveLockExpired,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    """Remove expired locks from channel states."""
    is_valid, msg, merkletree = is_valid_lock_expired(
        state_change=state_change,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
        receiver_state=channel_state.our_state,
        block_number=block_number,
    )

    events = list()
    if is_valid:
        channel_state.partner_state.balance_proof = state_change.balance_proof
        channel_state.partner_state.merkletree = merkletree

        _del_unclaimed_lock(channel_state.partner_state, state_change.secrethash)

        send_processed = SendProcessed(
            recipient=state_change.balance_proof.sender,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=state_change.message_identifier,
        )
        events = [send_processed]
    else:
        invalid_lock_expired = EventInvalidReceivedLockExpired(
            secrethash=state_change.secrethash,
            reason=msg,
        )
        events = [invalid_lock_expired]

    return TransitionResult(channel_state, events)


def handle_receive_lockedtransfer(
        channel_state: NettingChannelState,
        mediated_transfer: LockedTransferSignedState,
) -> EventsOrError:
    """Register the latest known transfer.

    The receiver needs to use this method to update the container with a
    _valid_ transfer, otherwise the locksroot will not contain the pending
    transfer. The receiver needs to ensure that the merkle root has the
    secrethash included, otherwise it won't be able to claim it.
    """
    is_valid, msg, merkletree = is_valid_lockedtransfer(
        mediated_transfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )

    if is_valid:
        channel_state.partner_state.balance_proof = mediated_transfer.balance_proof
        channel_state.partner_state.merkletree = merkletree

        lock = mediated_transfer.lock
        channel_state.partner_state.secrethashes_to_lockedlocks[lock.secrethash] = lock

        send_processed = SendProcessed(
            recipient=mediated_transfer.balance_proof.sender,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=mediated_transfer.message_identifier,
        )
        events = [send_processed]
    else:
        invalid_locked = EventInvalidReceivedLockedTransfer(
            payment_identifier=mediated_transfer.payment_identifier,
            reason=msg,
        )
        events = [invalid_locked]

    return is_valid, events, msg


def handle_receive_refundtransfercancelroute(
        channel_state: NettingChannelState,
        refund_transfer: ReceiveTransferRefundCancelRoute,
) -> EventsOrError:
    return handle_receive_lockedtransfer(channel_state, refund_transfer)


def handle_unlock(channel_state: NettingChannelState, unlock: ReceiveUnlock) -> EventsOrError:
    is_valid, msg, unlocked_merkletree = is_valid_unlock(
        unlock,
        channel_state,
        channel_state.partner_state,
    )

    if is_valid:
        channel_state.partner_state.balance_proof = unlock.balance_proof
        channel_state.partner_state.merkletree = unlocked_merkletree

        _del_lock(channel_state.partner_state, unlock.secrethash)

        send_processed = SendProcessed(
            recipient=unlock.balance_proof.sender,
            channel_identifier=CHANNEL_IDENTIFIER_GLOBAL_QUEUE,
            message_identifier=unlock.message_identifier,
        )
        events: typing.List[Event] = [send_processed]
    else:
        invalid_unlock = EventInvalidReceivedUnlock(
            secrethash=unlock.secrethash,
            reason=msg,
        )
        events = [invalid_unlock]

    return is_valid, events, msg


def handle_block(
        channel_state: NettingChannelState,
        state_change: Block,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    assert state_change.block_number == block_number

    events = list()

    if get_status(channel_state) == CHANNEL_STATE_CLOSED:
        closed_block_number = channel_state.close_transaction.finished_block_number
        settlement_end = closed_block_number + channel_state.settle_timeout

        if state_change.block_number > settlement_end:
            channel_state.settle_transaction = TransactionExecutionStatus(
                state_change.block_number,
                None,
                None,
            )
            event = ContractSendChannelSettle(
                channel_state.identifier,
                typing.TokenNetworkAddress(channel_state.token_network_identifier),
            )
            events.append(event)

    while is_deposit_confirmed(channel_state, block_number):
        order_deposit_transaction = heapq.heappop(channel_state.deposit_transaction_queue)
        apply_channel_newbalance(
            channel_state,
            order_deposit_transaction.transaction,
        )

    return TransitionResult(channel_state, events)


def handle_channel_closed(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelClosed,
) -> TransitionResult:
    events = list()

    just_closed = (
        state_change.channel_identifier == channel_state.identifier and
        get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED
    )

    if just_closed:
        set_closed(channel_state, state_change.block_number)

        balance_proof = channel_state.partner_state.balance_proof
        call_update = (
            state_change.transaction_from != channel_state.our_state.address and
            balance_proof is not None and
            channel_state.update_transaction is None
        )
        if call_update:
            expiration = state_change.block_number + channel_state.settle_timeout
            # The channel was closed by our partner, if there is a balance
            # proof available update this node half of the state
            update = ContractSendChannelUpdateTransfer(
                expiration,
                channel_state.identifier,
                channel_state.token_network_identifier,
                balance_proof,
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
        block_number: typing.BlockNumber,
) -> TransitionResult:
    if state_change.channel_identifier == channel_state.identifier:
        # update transfer was called, make sure we don't call it again
        channel_state.update_transaction = TransactionExecutionStatus(
            started_block_number=None,
            finished_block_number=block_number,
            result=TransactionExecutionStatus.SUCCESS,
        )

    return TransitionResult(channel_state, list())


def handle_channel_settled(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelSettled,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    events: typing.List[Event] = list()

    # At the moment each participant unlocks its receiving half of the
    # channel automatically
    if state_change.channel_identifier == channel_state.identifier:
        set_settled(channel_state, state_change.block_number)

        is_settle_pending = channel_state.our_unlock_transaction is not None
        merkle_tree_leaves = get_batch_unlock(channel_state.partner_state)

        if not is_settle_pending and merkle_tree_leaves:
            onchain_unlock = ContractSendChannelBatchUnlock(
                channel_state.token_address,
                channel_state.token_network_identifier,
                channel_state.identifier,
                channel_state.partner_state.address,
            )
            events.append(onchain_unlock)

            channel_state.our_unlock_transaction = TransactionExecutionStatus(
                block_number,
                None,
                None,
            )
        else:
            # we don't need to wait for the unlock to be successful, the
            # channel can be cleaned now
            channel_state = None

    return TransitionResult(channel_state, events)


def handle_channel_newbalance(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelNewBalance,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    deposit_transaction = state_change.deposit_transaction

    if is_transaction_confirmed(deposit_transaction.deposit_block_number, block_number):
        apply_channel_newbalance(channel_state, state_change.deposit_transaction)
    else:
        order = TransactionOrder(
            deposit_transaction.deposit_block_number,
            deposit_transaction,
        )
        heapq.heappush(channel_state.deposit_transaction_queue, order)

    events: typing.List[Event] = list()
    return TransitionResult(channel_state, events)


def apply_channel_newbalance(
        channel_state: NettingChannelState,
        deposit_transaction: TransactionChannelNewBalance,
) -> None:
    participant_address = deposit_transaction.participant_address
    contract_balance = deposit_transaction.contract_balance

    if participant_address == channel_state.our_state.address:
        update_contract_balance(channel_state.our_state, contract_balance)
    elif participant_address == channel_state.partner_state.address:
        update_contract_balance(channel_state.partner_state, contract_balance)


def handle_channel_batch_unlock(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelBatchUnlock,
) -> TransitionResult:
    events = list()

    # Unlock is allowed by the smart contract only on a settled channel.
    # Ignore the unlock if the channel was not closed yet.
    if get_status(channel_state) == CHANNEL_STATE_SETTLED:

        # Once our half of the channel is unlocked we can clean-up the channel
        if state_change.participant == channel_state.our_state.address:
            channel_state = None

    return TransitionResult(channel_state, events)


def state_transition(
        channel_state: NettingChannelState,
        state_change: StateChange,
        pseudo_random_generator: typing.Any,
        block_number: typing.BlockNumber,
) -> TransitionResult:
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    events: typing.List[Event] = list()
    iteration = TransitionResult(channel_state, events)

    if type(state_change) == Block:
        iteration = handle_block(
            channel_state,
            state_change,
            block_number,
        )
    elif type(state_change) == ActionChannelClose:
        iteration = handle_action_close(
            channel_state,
            state_change,
            block_number,
        )
    elif type(state_change) == ActionTransferDirect:
        iteration = handle_send_directtransfer(
            channel_state,
            state_change,
            pseudo_random_generator,
        )
    elif type(state_change) == ContractReceiveChannelClosed:
        iteration = handle_channel_closed(
            channel_state,
            state_change,
        )
    elif type(state_change) == ContractReceiveUpdateTransfer:
        iteration = handle_channel_updated_transfer(
            channel_state,
            state_change,
            block_number,
        )
    elif type(state_change) == ContractReceiveChannelSettled:
        iteration = handle_channel_settled(
            channel_state,
            state_change,
            block_number,
        )
    elif type(state_change) == ContractReceiveChannelNewBalance:
        iteration = handle_channel_newbalance(
            channel_state,
            state_change,
            block_number,
        )
    elif type(state_change) == ContractReceiveChannelBatchUnlock:
        iteration = handle_channel_batch_unlock(
            channel_state,
            state_change,
        )
    elif type(state_change) == ReceiveTransferDirect:
        iteration = handle_receive_directtransfer(
            channel_state,
            state_change,
        )

    return iteration
