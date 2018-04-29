# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import heapq
from binascii import hexlify
from collections import namedtuple

from raiden.encoding.signing import recover_publickey
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.balance_proof import signing_data
from raiden.transfer.events import (
    ContractSendChannelClose,
    ContractSendChannelSettle,
    ContractSendChannelUpdateTransfer,
    ContractSendChannelWithdraw,
    EventTransferReceivedInvalidDirectTransfer,
    EventTransferReceivedSuccess,
    EventTransferSentFailed,
    SendDirectTransfer,
    SendProcessed,
)
from raiden.transfer.mediated_transfer.state import LockedTransferUnsignedState
from raiden.transfer.mediated_transfer.events import (
    refund_from_sendmediated,
    SendBalanceProof,
    SendLockedTransfer,
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
    BalanceProofUnsignedState,
    HashTimeLockState,
    MerkleTreeState,
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
    ContractReceiveChannelWithdraw,
    ReceiveTransferDirect,
)
from raiden.utils import publickey_to_address, typing
from raiden.settings import DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK


TransactionOrder = namedtuple(
    'TransactionOrder',
    ('block_number', 'transaction')
)


def is_lock_pending(end_state, secrethash):
    """True if the `secrethash` corresponds to a lock that is pending withdraw
    and didn't expire.
    """
    return (
        secrethash in end_state.secrethashes_to_lockedlocks or
        secrethash in end_state.secrethashes_to_unlockedlocks
    )


def is_deposit_confirmed(channel_state, block_number):
    if not channel_state.deposit_transaction_queue:
        return False

    return is_transaction_confirmed(
        channel_state.deposit_transaction_queue[0].block_number,
        block_number,
    )


def is_lock_locked(end_state, secrethash):
    """True if the `secrethash` is for a lock with an unknown secret."""
    return secrethash in end_state.secrethashes_to_lockedlocks


def is_secret_known(end_state, secrethash):
    """True if the `secrethash` is for a lock with a known secret."""
    return secrethash in end_state.secrethashes_to_unlockedlocks


def is_transaction_confirmed(transaction_block_number, blockchain_block_number):
    confirmation_block = transaction_block_number + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK
    return blockchain_block_number > confirmation_block


def is_valid_signature(balance_proof, sender_address):
    data_that_was_signed = signing_data(
        balance_proof.nonce,
        balance_proof.transferred_amount,
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


def is_valid_directtransfer(direct_transfer, channel_state, sender_state, receiver_state):
    received_balance_proof = direct_transfer.balance_proof
    current_balance_proof = get_current_balanceproof(sender_state)

    current_locksroot, _, current_transferred_amount = current_balance_proof
    distributable = get_distributable(sender_state, receiver_state)
    expected_nonce = get_next_nonce(sender_state)

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
            "Invalid DirectTransfer message. "
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
            "Invalid DirectTransfer message. "
            "Balance proof's transferred_amount decreased, expected larger than: {} got: {}."
        ).format(
            current_transferred_amount,
            received_balance_proof.transferred_amount,
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


def is_valid_lockedtransfer(mediated_transfer, channel_state, sender_state, receiver_state):
    received_balance_proof = mediated_transfer.balance_proof
    current_balance_proof = get_current_balanceproof(sender_state)

    _, _, current_transferred_amount = current_balance_proof
    distributable = get_distributable(sender_state, receiver_state)
    expected_nonce = get_next_nonce(sender_state)

    lock = mediated_transfer.lock
    merkletree = compute_merkletree_with(sender_state.merkletree, lock.lockhash)

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
                "Invalid LockedTransfer message. "
                "Balance proof's locksroot didn't match, expected: {} got: {}."
            ).format(
                hexlify(locksroot_with_lock).decode(),
                hexlify(received_balance_proof.locksroot).decode(),
            )

            result = (False, msg, None)

        elif received_balance_proof.transferred_amount != current_transferred_amount:
            # Mediated transfers must not change transferred_amount
            msg = (
                "Invalid LockedTransfer message. "
                "Balance proof's transferred_amount changed, expected: {} got: {}."
            ).format(
                current_transferred_amount,
                received_balance_proof.transferred_amount,
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


def is_valid_unlock(unlock, channel_state, sender_state):
    received_balance_proof = unlock.balance_proof
    current_balance_proof = get_current_balanceproof(sender_state)

    lock = get_lock(sender_state, unlock.secrethash)

    if lock is not None:
        merkletree = compute_merkletree_without(sender_state.merkletree, lock.lockhash)
        locksroot_without_lock = merkleroot(merkletree)

        _, _, current_transferred_amount = current_balance_proof
        expected_nonce = get_next_nonce(sender_state)

        expected_transferred_amount = current_transferred_amount + lock.amount

        is_valid, signature_msg = is_valid_signature(
            received_balance_proof,
            sender_state.address,
        )

    # TODO: Accept unlock messages if the node has not yet sent a transaction
    # with the balance proof to the blockchain, this will save one call to
    # withdraw on-chain for the non-closing party.
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
            "Invalid Secret message. "
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


def get_amount_locked(end_state):
    total_pending = sum(
        lock.amount
        for lock in end_state.secrethashes_to_lockedlocks.values()
    )

    total_unclaimed = sum(
        unlock.lock.amount
        for unlock in end_state.secrethashes_to_unlockedlocks.values()
    )

    return total_pending + total_unclaimed


def get_balance(sender, receiver):
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


def get_current_balanceproof(end_state):
    balance_proof = end_state.balance_proof

    if balance_proof:
        locksroot = balance_proof.locksroot
        nonce = balance_proof.nonce
        transferred_amount = balance_proof.transferred_amount
    else:
        locksroot = EMPTY_MERKLE_ROOT
        nonce = 0
        transferred_amount = 0

    return (locksroot, nonce, transferred_amount)


def get_distributable(sender, receiver):
    return get_balance(sender, receiver) - get_amount_locked(sender)


def get_known_unlocks(end_state):
    """Generate unlocking proofs for the known secrets."""

    return [
        compute_proof_for_lock(
            end_state,
            partialproof.secret,
            partialproof.lock,
        )
        for partialproof in end_state.secrethashes_to_unlockedlocks.values()
    ]


def get_lock(
        end_state: 'NettingChannelEndState',
        secrethash: typing.Keccak256,
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


def get_next_nonce(end_state):
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


def _del_lock(end_state, secrethash):
    """Removes the lock from the indexing structures.

    Note:
        This won't change the merkletree!
    """
    assert is_lock_pending(end_state, secrethash)

    if secrethash in end_state.secrethashes_to_lockedlocks:
        del end_state.secrethashes_to_lockedlocks[secrethash]

    if secrethash in end_state.secrethashes_to_unlockedlocks:
        del end_state.secrethashes_to_unlockedlocks[secrethash]


def set_closed(channel_state, block_number):
    if not channel_state.close_transaction:
        channel_state.close_transaction = TransactionExecutionStatus(
            None,
            block_number,
            TransactionExecutionStatus.SUCCESS,
        )

    elif not channel_state.close_transaction.finished_block_number:
        channel_state.close_transaction.finished_block_number = block_number
        channel_state.close_transaction.result = TransactionExecutionStatus.SUCCESS


def set_settled(channel_state, block_number):
    if not channel_state.settle_transaction:
        channel_state.settle_transaction = TransactionExecutionStatus(
            None,
            block_number,
            TransactionExecutionStatus.SUCCESS,
        )

    elif not channel_state.settle_transaction.finished_block_number:
        channel_state.settle_transaction.finished_block_number = block_number
        channel_state.settle_transaction.result = TransactionExecutionStatus.SUCCESS


def update_contract_balance(end_state: 'NettingChannelEndState', contract_balance):
    if contract_balance > end_state.contract_balance:
        end_state.contract_balance = contract_balance


def compute_proof_for_lock(
        end_state: 'NettingChannelEndState',
        secret: typing.Secret,
        lock: HashTimeLockState
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
        lockhash: typing.Keccak256,
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


def compute_merkletree_without(merkletree, lockhash):
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
        registry_address,
        channel_state,
        amount,
        message_identifier,
        payment_identifier):

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

    nonce = get_next_nonce(our_state)
    token = channel_state.token_address
    recipient = partner_state.address

    balance_proof = BalanceProofUnsignedState(
        nonce,
        transferred_amount,
        locksroot,
        channel_state.identifier,
    )

    queue_name = channel_state.identifier
    direct_transfer = SendDirectTransfer(
        recipient,
        queue_name,
        message_identifier,
        payment_identifier,
        balance_proof,
        registry_address,
        token,
    )

    return direct_transfer


def create_sendlockedtransfer(
        registry_address,
        channel_state,
        initiator,
        target,
        amount,
        message_identifier,
        payment_identifier,
        expiration,
        secrethash):

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

    token = channel_state.token_address
    nonce = get_next_nonce(channel_state.our_state)
    recipient = channel_state.partner_state.address

    balance_proof = BalanceProofUnsignedState(
        nonce,
        transferred_amount,
        locksroot,
        channel_state.identifier,
    )

    locked_transfer = LockedTransferUnsignedState(
        payment_identifier,
        registry_address,
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


def create_unlock(channel_state, message_identifier, payment_identifier, secret, lock):
    msg = 'caller must make sure the lock is known'
    assert is_lock_pending(channel_state.our_state, lock.secrethash), msg

    msg = 'caller must make sure the channel is open'
    assert get_status(channel_state) == CHANNEL_STATE_OPENED, msg

    our_balance_proof = channel_state.our_state.balance_proof
    if our_balance_proof:
        transferred_amount = lock.amount + our_balance_proof.transferred_amount
    else:
        transferred_amount = lock.amount

    merkletree = compute_merkletree_without(
        channel_state.our_state.merkletree,
        lock.lockhash,
    )
    locksroot = merkleroot(merkletree)

    token = channel_state.token_address
    nonce = get_next_nonce(channel_state.our_state)
    recipient = channel_state.partner_state.address

    balance_proof = BalanceProofUnsignedState(
        nonce,
        transferred_amount,
        locksroot,
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
        registry_address,
        channel_state,
        amount,
        message_identifier,
        payment_identifier,
):
    direct_transfer = create_senddirecttransfer(
        registry_address,
        channel_state,
        amount,
        message_identifier,
        payment_identifier,
    )

    channel_state.our_state.balance_proof = direct_transfer.balance_proof

    return direct_transfer


def send_lockedtransfer(
        registry_address,
        channel_state,
        initiator,
        target,
        amount,
        message_identifier,
        payment_identifier,
        expiration,
        secrethash,
):
    send_locked_transfer_event, merkletree = create_sendlockedtransfer(
        registry_address,
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
        registry_address,
        channel_state,
        initiator,
        target,
        amount,
        message_identifier,
        payment_identifier,
        expiration,
        secrethash):

    msg = 'Refunds are only valid for *know and pending* transfers'
    assert secrethash in channel_state.partner_state.secrethashes_to_lockedlocks, msg

    send_mediated_transfer, merkletree = create_sendlockedtransfer(
        registry_address,
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
        channel_state,
        message_identifier,
        payment_identifier,
        secret,
        secrethash,
):
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


def events_for_close(channel_state, block_number):
    events = list()

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED:
        channel_state.close_transaction = TransactionExecutionStatus(
            block_number,
            None,
            None
        )

        close_event = ContractSendChannelClose(
            channel_state.identifier,
            channel_state.token_address,
            channel_state.partner_state.balance_proof,
        )

        events.append(close_event)

    return events


def register_secret_endstate(end_state, secret, secrethash):
    if is_lock_locked(end_state, secrethash):
        pendinglock = end_state.secrethashes_to_lockedlocks[secrethash]
        del end_state.secrethashes_to_lockedlocks[secrethash]

        end_state.secrethashes_to_unlockedlocks[secrethash] = UnlockPartialProofState(
            pendinglock,
            secret,
        )


def register_secret(channel_state, secret, secrethash):
    """This will register the secret and set the lock to the unlocked stated.

    Even though the lock is unlock it's is *not* claimed. The capacity will
    increase once the next balance proof is received.
    """
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state

    register_secret_endstate(our_state, secret, secrethash)
    register_secret_endstate(partner_state, secret, secrethash)


def handle_send_directtransfer(
        channel_state,
        state_change,
        pseudo_random_generator,
):
    events = list()

    amount = state_change.amount
    payment_identifier = state_change.payment_identifier
    distributable_amount = get_distributable(channel_state.our_state, channel_state.partner_state)

    is_open = get_status(channel_state) == CHANNEL_STATE_OPENED
    is_valid = amount > 0
    can_pay = amount <= distributable_amount

    if is_open and is_valid and can_pay:
        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        direct_transfer = send_directtransfer(
            state_change.payment_network_identifier,
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


def handle_action_close(channel_state, close, block_number):
    msg = 'caller must make sure the ids match'
    assert channel_state.identifier == close.channel_identifier, msg

    events = events_for_close(channel_state, block_number)
    return TransitionResult(channel_state, events)


def handle_receive_directtransfer(channel_state, direct_transfer):
    is_valid, msg = is_valid_directtransfer(
        direct_transfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )

    if is_valid:
        _, _, previous_transferred_amount = get_current_balanceproof(channel_state.partner_state)
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
        channel_state: 'NettingChannelState',
        mediated_transfer: 'LockedTransferSignedState'
):
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


def handle_receive_refundtransfer(channel_state, refund_transfer):
    return handle_receive_lockedtransfer(channel_state, refund_transfer)


def handle_receive_secretreveal(channel_state, state_change):
    secret = state_change.secret
    secrethash = state_change.secrethash

    register_secret(channel_state, secret, secrethash)


def handle_unlock(channel_state, unlock):
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


def handle_block(channel_state, state_change, block_number):
    assert state_change.block_number == block_number

    events = list()

    if get_status(channel_state) == CHANNEL_STATE_CLOSED:
        closed_block_number = channel_state.close_transaction.finished_block_number
        settlement_end = closed_block_number + channel_state.settle_timeout

        if state_change.block_number > settlement_end:
            channel_state.settle_transaction = TransactionExecutionStatus(
                state_change.block_number,
                None,
                None
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


def handle_channel_closed(channel_state, state_change):
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
            withdraw = ContractSendChannelWithdraw(
                channel_state.identifier,
                unlock_proofs,
            )
            events.append(withdraw)

    return TransitionResult(channel_state, events)


def handle_channel_settled(channel_state, state_change):
    events = list()

    if state_change.channel_identifier == channel_state.identifier:
        set_settled(channel_state, state_change.settle_block_number)

    return TransitionResult(channel_state, events)


def handle_channel_newbalance(channel_state, state_change, block_number):
    deposit_transaction = state_change.deposit_transaction

    if is_transaction_confirmed(deposit_transaction.deposit_block_number, block_number):
        apply_channel_newbalance(channel_state, state_change.deposit_transaction)
    else:
        order = TransactionOrder(
            deposit_transaction.deposit_block_number,
            deposit_transaction,
        )
        heapq.heappush(channel_state.deposit_transaction_queue, order)

    events = list()
    return TransitionResult(channel_state, events)


def apply_channel_newbalance(channel_state, deposit_transaction):
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


def handle_channel_withdraw(channel_state, state_change):
    events = list()

    # Withdraw is allowed by the smart contract only on a closed channel.
    # Ignore the withdraw if the channel was not closed yet.
    if get_status(channel_state) == CHANNEL_STATE_CLOSED:
        our_state = channel_state.our_state
        partner_state = channel_state.partner_state

        secrethash = state_change.secrethash
        secret = state_change.secret

        our_withdraw = (
            state_change.receiver == our_state.address and
            is_lock_pending(partner_state, secrethash)
        )
        if our_withdraw:
            _del_lock(partner_state, secrethash)

        partner_withdraw = (
            state_change.receiver == partner_state.address and
            is_lock_pending(our_state, secrethash)
        )
        if partner_withdraw:
            _del_lock(our_state, secrethash)

        # Withdraw is required if there was a refund in this channel, and the
        # secret is learned from the withdraw event.
        if is_lock_pending(our_state, secrethash):
            lock = get_lock(our_state, secrethash)
            proof = compute_proof_for_lock(our_state, secret, lock)
            withdraw = ContractSendChannelWithdraw(channel_state.identifier, [proof])
            events.append(withdraw)

        register_secret(channel_state, secret, secrethash)

    return TransitionResult(channel_state, events)


def state_transition(
        channel_state,
        state_change,
        pseudo_random_generator,
        block_number,
):
    # pylint: disable=too-many-branches,unidiomatic-typecheck

    events = list()
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

    elif type(state_change) == ContractReceiveChannelSettled:
        iteration = handle_channel_settled(channel_state, state_change)

    elif type(state_change) == ContractReceiveChannelNewBalance:
        iteration = handle_channel_newbalance(channel_state, state_change, block_number)

    elif type(state_change) == ContractReceiveChannelWithdraw:
        iteration = handle_channel_withdraw(channel_state, state_change)

    elif type(state_change) == ReceiveTransferDirect:
        iteration = handle_receive_directtransfer(channel_state, state_change)

    return iteration
