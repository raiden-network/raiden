# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import heapq
from binascii import hexlify
from collections import namedtuple

from raiden.constants import UINT256_MAX
from raiden.transfer.architecture import StateChange, Event
from raiden.encoding.signing import recover_publickey
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.balance_proof import signing_data
from raiden.transfer.events import (
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelBatchUnlock,
    EventTransferReceivedInvalidDirectTransfer,
    EventTransferReceivedSuccess,
    EventTransferSentFailed,
    SendDirectTransfer,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    LockedTransferUnsignedState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.mediated_transfer.events import (
    refund_from_sendmediated,
    SendBalanceProof,
    SendLockedTransfer,
    SendRefundTransfer,
)
from raiden.transfer.merkle_tree import (
    LEAVES,
    merkleroot,
    compute_layers,
    compute_merkleproof_for,
)
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    CHANNEL_STATE_UNUSABLE,
    EMPTY_MERKLE_ROOT,
    EMPTY_MERKLE_TREE,
    message_identifier_from_prng,
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    HashTimeLockState,
    MerkleTreeState,
    NettingChannelEndState,
    NettingChannelState,
    TransactionChannelNewBalance,
    TransactionExecutionStatus,
    UnlockPartialProofState,
    UnlockProofState,
)
from raiden.transfer.state_change import (
    ActionChannelClose,
    ActionTransferDirect,
    Block,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveChannelUnlock,
    ReceiveTransferDirect,
    ReceiveUnlock,
)
from raiden.utils import publickey_to_address, typing
from raiden.settings import DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK

# This should be changed to `Union[str, MerkleTreeState]`
MerkletreeOrError = typing.Tuple[bool, typing.Optional[str], typing.Any]
EventsOrError = typing.Tuple[bool, typing.List[Event], typing.Any]
BalanceProofData = typing.Tuple[typing.Locksroot, typing.Nonce, typing.TokenAmount]
SendUnlockAndMerkleTree = typing.Tuple[SendBalanceProof, MerkleTreeState]


TransactionOrder = namedtuple(
    'TransactionOrder',
    ('block_number', 'transaction'),
)


def is_lock_pending(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> bool:
    """True if the `secrethash` corresponds to a lock that is pending to be claimed
    and didn't expire.
    """
    return (
        secrethash in end_state.secrethashes_to_lockedlocks or
        secrethash in end_state.secrethashes_to_unlockedlocks
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


def is_secret_known(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> bool:
    """True if the `secrethash` is for a lock with a known secret."""
    return secrethash in end_state.secrethashes_to_unlockedlocks


def get_secret(
        end_state: NettingChannelEndState,
        secrethash: typing.SecretHash,
) -> typing.Optional[typing.Secret]:
    """Returns `secret` if the `secrethash` is for a lock with a known secret."""
    if is_secret_known(end_state, secrethash):
        return end_state.secrethashes_to_unlockedlocks[secrethash].secret

    return None


def is_transaction_confirmed(
        transaction_block_number: typing.BlockNumber,
        blockchain_block_number: typing.BlockNumber,
) -> bool:
    confirmation_block = transaction_block_number + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK
    return blockchain_block_number > confirmation_block


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
    data_that_was_signed = signing_data(
        balance_proof.nonce,
        balance_proof.transferred_amount,
        balance_proof.locked_amount,
        balance_proof.channel_address,
        balance_proof.locksroot,
        balance_proof.message_hash,
    )

    try:
        # ValueError is raised if the PublicKey instantiation failed, let it
        # propagate because it's a memory pressure problem
        publickey = recover_publickey(
            data_that_was_signed,
            balance_proof.signature,
        )
    except Exception:  # pylint: disable=broad-except
        # secp256k1 is using bare Exception classes
        # raised if the recovery failed
        msg = 'Signature invalid, could not be recovered.'
        return (False, msg)

    is_correct_sender = sender_address == publickey_to_address(publickey)
    if is_correct_sender:
        return (True, None)

    msg = 'Signature was valid but the expected address does not match.'
    return (False, msg)


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
    expected_nonce = get_next_nonce(sender_state)
    transferred_amount_after_unlock = (
        received_balance_proof.transferred_amount +
        received_balance_proof.locked_amount
    )

    amount = received_balance_proof.transferred_amount - current_transferred_amount

    is_valid, signature_msg = is_valid_signature(
        received_balance_proof,
        sender_state.address,
    )

    if get_status(channel_state) != CHANNEL_STATE_OPENED:
        msg = 'Invalid direct message. The channel is already closed.'
        result = (False, msg)

    elif not is_valid:
        # The signature must be valid, otherwise the balance proof cannot be
        # used onchain.
        msg = 'Invalid DirectTransfer message. {}'.format(signature_msg)

        result = (False, msg)

    elif received_balance_proof.nonce != expected_nonce:
        # The nonces must increase sequentially, otherwise there is a
        # synchronization problem.
        msg = (
            'Invalid DirectTransfer message. '
            'Nonce did not change sequentially, expected: {} got: {}.'
        ).format(
            expected_nonce,
            received_balance_proof.nonce,
        )

        result = (False, msg)

    elif received_balance_proof.locksroot != current_locksroot:
        # Direct transfers do not use hash time lock, so it cannot change the
        # locksroot, otherwise a lock could be removed.
        msg = (
            'Invalid DirectTransfer message. '
            "Balance proof's locksroot changed, expected: {} got: {}."
        ).format(
            hexlify(current_locksroot).decode(),
            hexlify(received_balance_proof.locksroot).decode(),
        )

        result = (False, msg)

    elif received_balance_proof.transferred_amount <= current_transferred_amount:
        # Direct transfers must increase the transferred_amount, otherwise the
        # sender is trying to play the protocol and steal token.
        msg = (
            'Invalid DirectTransfer message. '
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
            'Invalid DirectTransfer message. '
            "Balance proof's locked_amount is invalid, expected: {} got: {}."
        ).format(
            current_locked_amount,
            received_balance_proof.locked_amount,
        )

        result = (False, msg)

    elif not is_valid_amount(sender_state, amount):
        # Some serialization formats allow values to be larger than the maximum
        msg = (
            "Invalid DirectTransfer message. "
            "Balance proof's transferred_amount + locked_amount is larger than the maximum value. "
            "max: {} got: {}"
        ).format(
            UINT256_MAX,
            transferred_amount_after_unlock,
        )

        result = (False, msg)

    elif received_balance_proof.channel_address != channel_state.identifier:
        # The balance proof must be tied to this channel, otherwise the
        # on-chain contract would be sucesstible to replay attacks across
        # channels.
        msg = (
            'Invalid DirectTransfer message. '
            'Balance proof is tied to the wrong channel, expected: {} got: {}'
        ).format(
            hexlify(channel_state.identifier).decode(),
            hexlify(received_balance_proof.channel_address).decode(),
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
        mediated_transfer: LockedTransferSignedState,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
        receiver_state: NettingChannelEndState,
) -> MerkletreeOrError:
    received_balance_proof = mediated_transfer.balance_proof
    current_balance_proof = get_current_balanceproof(sender_state)

    lock = mediated_transfer.lock
    merkletree = compute_merkletree_with(sender_state.merkletree, lock.lockhash)

    _, _, current_transferred_amount, current_locked_amount = current_balance_proof
    distributable = get_distributable(sender_state, receiver_state)
    expected_nonce = get_next_nonce(sender_state)
    expected_locked_amount = current_locked_amount + lock.amount
    transferred_amount_after_unlock = (
        received_balance_proof.transferred_amount +
        expected_locked_amount
    )

    if get_status(channel_state) != CHANNEL_STATE_OPENED:
        msg = 'Invalid direct message. The channel is already closed.'
        result = (False, msg, None)

    if merkletree is None:
        msg = 'Invalid LockedTransfer message. Same lockhash handled twice.'
        result = (False, msg, None)

    else:
        locksroot_with_lock = merkleroot(merkletree)

        (is_valid, signature_msg) = is_valid_signature(
            received_balance_proof,
            sender_state.address,
        )

        if not is_valid:
            # The signature must be valid, otherwise the balance proof cannot be
            # used onchain
            msg = 'Invalid LockedTransfer message. {}'.format(signature_msg)

            result = (False, msg, None)

        elif received_balance_proof.nonce != expected_nonce:
            # The nonces must increase sequentially, otherwise there is a
            # synchronization problem
            msg = (
                'Invalid LockedTransfer message. '
                'Nonce did not change sequentially, expected: {} got: {}.'
            ).format(
                expected_nonce,
                received_balance_proof.nonce,
            )

            result = (False, msg, None)

        elif received_balance_proof.locksroot != locksroot_with_lock:
            # The locksroot must be updated to include the new lock
            msg = (
                'Invalid LockedTransfer message. '
                "Balance proof's locksroot didn't match, expected: {} got: {}."
            ).format(
                hexlify(locksroot_with_lock).decode(),
                hexlify(received_balance_proof.locksroot).decode(),
            )

            result = (False, msg, None)

        elif received_balance_proof.transferred_amount != current_transferred_amount:
            # Mediated transfers must not change transferred_amount
            msg = (
                'Invalid LockedTransfer message. '
                "Balance proof's transferred_amount changed, expected: {} got: {}."
            ).format(
                current_transferred_amount,
                received_balance_proof.transferred_amount,
            )

            result = (False, msg, None)

        elif not is_valid_amount(sender_state, lock.amount):
            # We can validate that the Unlock message will have a transferred
            # amount, accepting a lock that cannot be unlocked is useless
            msg = (
                "Invalid LockedTransfer message. "
                "Unlocking the lock would result in an overflow. max: {} result would be: {}"
            ).format(
                UINT256_MAX,
                transferred_amount_after_unlock,
            )

            result = (False, msg, None)

        elif received_balance_proof.locked_amount != expected_locked_amount:
            # Mediated transfers must increase the locked_amount by lock.amount
            msg = (
                'Invalid LockedTransfer message. '
                "Balance proof's locked_amount is invalid, expected: {} got: {}."
            ).format(
                expected_locked_amount,
                received_balance_proof.locked_amount,
            )

            result = (False, msg, None)

        elif received_balance_proof.channel_address != channel_state.identifier:
            # The balance proof must be tied to this channel, otherwise the
            # on-chain contract would be sucesstible to replay attacks across
            # channels.
            msg = (
                'Invalid LockedTransfer message. '
                'Balance proof is tied to the wrong channel, expected: {} got: {}'
            ).format(
                hexlify(channel_state.identifier).decode(),
                hexlify(received_balance_proof.channel_address).decode(),
            )
            result = (False, msg, None)

        # the locked amount is limited to the current available balance, otherwise
        # the sender is doing a trying to play the protocol and do a double spend
        elif lock.amount > distributable:
            msg = (
                'Invalid LockedTransfer message. '
                'Lock amount larger than the available distributable, '
                'lock amount: {} maximum distributable: {}'
            ).format(
                lock.amount,
                distributable,
            )

            result = (False, msg, None)

        else:
            result = (True, None, merkletree)

    return result


def is_valid_unlock(
        unlock: ReceiveUnlock,
        channel_state: NettingChannelState,
        sender_state: NettingChannelEndState,
) -> MerkletreeOrError:
    received_balance_proof = unlock.balance_proof
    current_balance_proof = get_current_balanceproof(sender_state)

    lock = get_lock(sender_state, unlock.secrethash)

    if lock is not None:
        merkletree = compute_merkletree_without(sender_state.merkletree, lock.lockhash)
        locksroot_without_lock = merkleroot(merkletree)

        _, _, current_transferred_amount, _ = current_balance_proof
        expected_nonce = get_next_nonce(sender_state)

        expected_transferred_amount = (
            current_transferred_amount +
            typing.TokenAmount(lock.amount)
        )

        is_valid, signature_msg = is_valid_signature(
            received_balance_proof,
            sender_state.address,
        )

    # TODO: Accept unlock messages if the node has not yet sent a transaction
    # with the balance proof to the blockchain, this will save one call to
    # unlock on-chain for the non-closing party.
    if get_status(channel_state) != CHANNEL_STATE_OPENED:
        msg = 'Invalid Unlock message for {}. The channel is already closed.'.format(
            hexlify(unlock.secrethash).decode(),
        )

        result = (False, msg, None)

    elif lock is None:
        msg = 'Invalid Secret message. There is no correspoding lock for {}'.format(
            hexlify(unlock.secrethash).decode(),
        )

        result = (False, msg, None)

    elif not is_valid:
        # The signature must be valid, otherwise the balance proof cannot be
        # used onchain.
        msg = 'Invalid Secret message. {}'.format(signature_msg)

        result = (False, msg, None)

    elif received_balance_proof.nonce != expected_nonce:
        # The nonces must increase sequentially, otherwise there is a
        # synchronization problem.
        msg = (
            'Invalid Secret message. '
            'Nonce did not change sequentially, expected: {} got: {}.'
        ).format(
            expected_nonce,
            received_balance_proof.nonce,
        )

        result = (False, msg, None)

    elif received_balance_proof.locksroot != locksroot_without_lock:
        # Secret messages remove a known lock, the new locksroot must have only
        # that lock removed, otherwise the sender may be trying to remove
        # additional locks.
        msg = (
            'Invalid Secret message. '
            "Balance proof's locksroot didn't match, expected: {} got: {}."
        ).format(
            hexlify(locksroot_without_lock).decode(),
            hexlify(received_balance_proof.locksroot).decode(),
        )

        result = (False, msg, None)

    elif received_balance_proof.transferred_amount != expected_transferred_amount:
        # Secret messages must increase the transferred_amount by lock amount,
        # otherwise the sender is trying to play the protocol and steal token.
        msg = (
            "Invalid Secret message. "
            "Balance proof's wrong transferred_amount, expected: {} got: {}."
        ).format(
            expected_transferred_amount,
            received_balance_proof.transferred_amount,
        )

        result = (False, msg, None)

    elif received_balance_proof.transferred_amount > UINT256_MAX:
        # Some serialization formats allow values to be larger than the maximum
        msg = (
            "Invalid Secret message. "
            "Balance proof's transferred_amount is larger than the maximum value. max: {} got: {}"
        ).format(
            UINT256_MAX,
            received_balance_proof.transferred_amount,
        )

        result = (False, msg, None)

    elif received_balance_proof.channel_address != channel_state.identifier:
        # The balance proof must be tied to this channel, otherwise the
        # on-chain contract would be sucesstible to replay attacks across
        # channels.
        msg = (
            'Invalid Secret message. '
            'Balance proof is tied to the wrong channel, expected: {} got: {}'
        ).format(
            channel_state.identifier,
            hexlify(received_balance_proof.channel_address).decode(),
        )
        result = (False, msg, None)

    else:
        result = (True, None, merkletree)

    return result


def get_amount_locked(end_state: NettingChannelEndState) -> typing.Balance:
    total_pending = sum(
        lock.amount
        for lock in end_state.secrethashes_to_lockedlocks.values()
    )

    total_unclaimed = sum(
        unlock.lock.amount
        for unlock in end_state.secrethashes_to_unlockedlocks.values()
    )

    return total_pending + total_unclaimed


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
        transferred_amount = 0
        locked_amount = 0

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


def get_known_unlocks(end_state: NettingChannelEndState) -> typing.List[UnlockProofState]:
    """Generate unlocking proofs for the known secrets."""

    return [
        compute_proof_for_lock(
            end_state,
            partialproof.secret,
            partialproof.lock,
        )
        for partialproof in end_state.secrethashes_to_unlockedlocks.values()
    ]


def get_batch_unlock(
        end_state: NettingChannelEndState,
) -> typing.Optional[typing.MerkleTreeLeaves]:
    """ Unlock proof for an entire merkle tree of pending locks

    The unlock proof contains all the merkle tree data, tightly packed, needed by the token
    network contract to verify the secret expiry and calculate the token amounts to transfer.
    """

    if len(end_state.merkletree.layers[LEAVES]) == 0:
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

    all_locks_packed = b''.join(
        lockhashes_to_locks[lockhash].encoded for lockhash in end_state.merkletree.layers[LEAVES]
    )

    return all_locks_packed


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

        if partial_unlock:
            lock = partial_unlock.lock

    assert isinstance(lock, HashTimeLockState) or lock is None
    return lock


def get_next_nonce(end_state: NettingChannelEndState) -> typing.Nonce:
    if end_state.balance_proof:
        return end_state.balance_proof.nonce + 1

    # 0 must not be used since in the netting contract it represents null.
    return 1


def get_status(channel_state):
    if channel_state.settle_transaction:
        finished_sucessfully = (
            channel_state.settle_transaction.result == TransactionExecutionStatus.SUCCESS
        )
        running = channel_state.settle_transaction.finished_block_number is None

        if finished_sucessfully:
            result = CHANNEL_STATE_SETTLED
        elif running:
            result = CHANNEL_STATE_SETTLING
        else:
            result = CHANNEL_STATE_UNUSABLE

    elif channel_state.close_transaction:
        finished_sucessfully = (
            channel_state.close_transaction.result == TransactionExecutionStatus.SUCCESS
        )
        running = channel_state.close_transaction.finished_block_number is None

        if finished_sucessfully:
            result = CHANNEL_STATE_CLOSED
        elif running:
            result = CHANNEL_STATE_CLOSING
        else:
            result = CHANNEL_STATE_UNUSABLE

    else:
        result = CHANNEL_STATE_OPENED

    return result


def _del_lock(end_state: NettingChannelEndState, secrethash: typing.SecretHash) -> None:
    """Removes the lock from the indexing structures.

    Note:
        This won't change the merkletree!
    """
    assert is_lock_pending(end_state, secrethash)

    if secrethash in end_state.secrethashes_to_lockedlocks:
        del end_state.secrethashes_to_lockedlocks[secrethash]

    if secrethash in end_state.secrethashes_to_unlockedlocks:
        del end_state.secrethashes_to_unlockedlocks[secrethash]


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
    token = channel_state.token_address
    recipient = partner_state.address
    locked_amount = get_amount_locked(our_state)

    balance_proof = BalanceProofUnsignedState(
        nonce,
        transferred_amount,
        locked_amount,
        locksroot,
        channel_state.token_network_identifier,
        channel_state.identifier,
    )

    queue_name = channel_state.identifier
    direct_transfer = SendDirectTransfer(
        recipient,
        queue_name,
        message_identifier,
        payment_identifier,
        balance_proof,
        token,
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
) -> SendLockedTransfer:
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
        nonce,
        transferred_amount,
        locked_amount,
        locksroot,
        channel_state.token_network_identifier,
        channel_state.identifier,
    )

    locked_transfer = LockedTransferUnsignedState(
        payment_identifier,
        token,
        balance_proof,
        lock,
        initiator,
        target,
    )

    queue_name = channel_state.identifier
    lockedtransfer = SendLockedTransfer(
        recipient,
        queue_name,
        message_identifier,
        locked_transfer,
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

    token = channel_state.token_address
    nonce = get_next_nonce(our_state)
    recipient = channel_state.partner_state.address
    locked_amount = get_amount_locked(our_state) - lock.amount  # the lock is still registered

    balance_proof = BalanceProofUnsignedState(
        nonce,
        transferred_amount,
        locked_amount,
        locksroot,
        channel_state.token_network_identifier,
        channel_state.identifier,
    )

    queue_name = channel_state.identifier
    unlock_lock = SendBalanceProof(
        recipient,
        queue_name,
        message_identifier,
        payment_identifier,
        token,
        secret,
        balance_proof,
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
    msg = 'Refunds are only valid for *know and pending* transfers'
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
            channel_state.partner_state.balance_proof,
        )

        events.append(close_event)

    return events


def register_secret_endstate(
        end_state: NettingChannelEndState,
        secret: typing.Secret,
        secrethash: typing.SecretHash,
) -> None:
    if is_lock_locked(end_state, secrethash):
        pendinglock = end_state.secrethashes_to_lockedlocks[secrethash]
        del end_state.secrethashes_to_lockedlocks[secrethash]

        end_state.secrethashes_to_unlockedlocks[secrethash] = UnlockPartialProofState(
            pendinglock,
            secret,
        )


def register_secret(
        channel_state: NettingChannelState,
        secret: typing.Secret,
        secrethash: typing.SecretHash,
) -> None:
    """This will register the secret and set the lock to the unlocked stated.

    Even though the lock is unlock it's is *not* claimed. The capacity will
    increase once the next balance proof is received.
    """
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state

    register_secret_endstate(our_state, secret, secrethash)
    register_secret_endstate(partner_state, secret, secrethash)


def handle_send_directtransfer(
        channel_state: NettingChannelState,
        state_change: ActionTransferDirect,
        pseudo_random_generator: typing.Any,
) -> TransitionResult:
    events: typing.List[Event] = list()

    amount = state_change.amount
    payment_identifier = state_change.payment_identifier
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
            failure = EventTransferSentFailed(payment_identifier, 'Channel is not opened')
            events.append(failure)

        elif not is_valid:
            msg = 'Transfer amount is invalid. Transfer: {}'.format(amount)
            failure = EventTransferSentFailed(payment_identifier, msg)
            events.append(failure)

        elif not can_pay:
            msg = (
                'Transfer amount exceeds the available capacity. '
                'Capacity: {}, Transfer: {}'
            ).format(
                distributable_amount,
                amount,
            )

            failure = EventTransferSentFailed(payment_identifier, msg)
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
        transfer_sucess_event = EventTransferReceivedSuccess(
            direct_transfer.payment_identifier,
            transfer_amount,
            channel_state.partner_state.address,
        )
        send_processed = SendProcessed(
            direct_transfer.balance_proof.sender,
            b'global',
            direct_transfer.message_identifier,
        )
        events = [transfer_sucess_event, send_processed]
    else:
        transfer_invalid_event = EventTransferReceivedInvalidDirectTransfer(
            direct_transfer.payment_identifier,
            reason=msg,
        )
        events = [transfer_invalid_event]

    return TransitionResult(channel_state, events)


def handle_receive_lockedtransfer(
        channel_state: NettingChannelState,
        mediated_transfer: LockedTransferSignedState,
) -> TransitionResult:
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
            mediated_transfer.balance_proof.sender,
            b'global',
            mediated_transfer.message_identifier,
        )
        events = [send_processed]
    else:
        events = list()

    return is_valid, events, msg


def handle_receive_refundtransfercancelroute(
        channel_state: NettingChannelState,
        refund_transfer: ReceiveTransferRefundCancelRoute,
) -> TransitionResult:
    return handle_receive_lockedtransfer(channel_state, refund_transfer)


def handle_unlock(channel_state: NettingChannelState, unlock: ReceiveUnlock) -> EventsOrError:
    events: typing.List[Event]

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
            unlock.balance_proof.sender,
            b'global',
            unlock.message_identifier,
        )
        events = [send_processed]
    else:
        events = list()

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
            event = ContractSendChannelSettle(channel_state.identifier)
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
        set_closed(channel_state, state_change.closed_block_number)

        balance_proof = channel_state.partner_state.balance_proof
        call_update = (
            state_change.closing_address != channel_state.our_state.address and
            balance_proof
        )
        if call_update:
            # The channel was closed by our partner, if there is a balance
            # proof available update this node half of the state
            update = ContractSendChannelUpdateTransfer(
                channel_state.identifier,
                balance_proof,
            )
            events.append(update)

        unlock_proofs = get_known_unlocks(channel_state.partner_state)
        if unlock_proofs:
            onchain_unlock = ContractSendChannelBatchUnlock(
                channel_state.identifier,
                unlock_proofs,
            )
            events.append(onchain_unlock)

    return TransitionResult(channel_state, events)


def handle_channel_closed2(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelClosed,
) -> TransitionResult:
    events = list()

    just_closed = (
        state_change.channel_identifier == channel_state.identifier and
        get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED
    )

    if just_closed:
        set_closed(channel_state, state_change.closed_block_number)

        balance_proof = channel_state.partner_state.balance_proof
        call_update = (
            state_change.closing_address != channel_state.our_state.address and
            balance_proof
        )
        if call_update:
            # The channel was closed by our partner, if there is a balance
            # proof available update this node half of the state
            update = ContractSendChannelUpdateTransfer(
                channel_state.identifier,
                balance_proof,
            )
            events.append(update)

    return TransitionResult(channel_state, events)


def handle_channel_settled(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelSettled,
) -> TransitionResult:
    events: typing.List[Event] = list()

    if state_change.channel_identifier == channel_state.identifier:
        set_settled(channel_state, state_change.settle_block_number)

    return TransitionResult(channel_state, events)


def handle_channel_settled2(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelSettled,
) -> TransitionResult:
    events: typing.List[Event] = list()

    if state_change.channel_identifier == channel_state.identifier:
        set_settled(channel_state, state_change.settle_block_number)

        unlock_proofs = get_batch_unlock(channel_state.partner_state)
        if unlock_proofs:
            onchain_unlock = ContractSendChannelBatchUnlock(
                channel_state.identifier,
                unlock_proofs,
            )
            events.append(onchain_unlock)

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

    if participant_address == channel_state.our_state.address:
        new_balance = max(
            channel_state.our_state.contract_balance,
            deposit_transaction.contract_balance,
        )
        channel_state.our_state.contract_balance = new_balance

    elif participant_address == channel_state.partner_state.address:
        new_balance = max(
            channel_state.partner_state.contract_balance,
            deposit_transaction.contract_balance,
        )
        channel_state.partner_state.contract_balance = new_balance


def handle_channel_unlock(
        channel_state: NettingChannelState,
        state_change: ContractReceiveChannelUnlock,
) -> TransitionResult:
    events = list()

    # Unlock is allowed by the smart contract only on a closed channel.
    # Ignore the unlock if the channel was not closed yet.
    if get_status(channel_state) == CHANNEL_STATE_CLOSED:
        our_state = channel_state.our_state
        partner_state = channel_state.partner_state

        secrethash = state_change.secrethash
        secret = state_change.secret

        our_unlock = (
            state_change.receiver == our_state.address and
            is_lock_pending(partner_state, secrethash)
        )
        if our_unlock:
            _del_lock(partner_state, secrethash)

        partner_unlock = (
            state_change.receiver == partner_state.address and
            is_lock_pending(our_state, secrethash)
        )
        if partner_unlock:
            _del_lock(our_state, secrethash)

        # Unlock is required if there was a refund in this channel, and the
        # secret is learned from the unlock event.
        if is_lock_pending(our_state, secrethash):
            lock = get_lock(our_state, secrethash)
            proof = compute_proof_for_lock(our_state, secret, lock)
            unlock = ContractSendChannelBatchUnlock(channel_state.identifier, [proof])
            events.append(unlock)

        register_secret(channel_state, secret, secrethash)

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
        iteration = handle_block(channel_state, state_change, block_number)

    elif type(state_change) == ActionChannelClose:
        iteration = handle_action_close(channel_state, state_change, block_number)

    elif type(state_change) == ActionTransferDirect:
        iteration = handle_send_directtransfer(
            channel_state,
            state_change,
            pseudo_random_generator,
        )

    elif type(state_change) == ContractReceiveChannelClosed:
        iteration = handle_channel_closed(channel_state, state_change)
        # iteration = handle_channel_closed2(channel_state, state_change)

    elif type(state_change) == ContractReceiveChannelSettled:
        iteration = handle_channel_settled(channel_state, state_change)
        # iteration = handle_channel_settled2(channel_state, state_change)

    elif type(state_change) == ContractReceiveChannelNewBalance:
        iteration = handle_channel_newbalance(channel_state, state_change, block_number)

    elif type(state_change) == ContractReceiveChannelUnlock:
        iteration = handle_channel_unlock(channel_state, state_change)

    elif type(state_change) == ReceiveTransferDirect:
        iteration = handle_receive_directtransfer(channel_state, state_change)

    return iteration
