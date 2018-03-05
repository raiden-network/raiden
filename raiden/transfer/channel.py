# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
from binascii import hexlify

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
)
from raiden.transfer.mediated_transfer.state import LockedTransferUnsignedState
from raiden.transfer.mediated_transfer.events import (
    refund_from_sendmediated,
    SendBalanceProof2,
    SendMediatedTransfer2,
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
    ReceiveTransferDirect2,
)
from raiden.utils import publickey_to_address, typing


def is_known(end_state, hashlock):
    """True if the `hashlock` corresponds to a known lock."""
    return (
        hashlock in end_state.hashlocks_to_pendinglocks or
        hashlock in end_state.hashlocks_to_unclaimedlocks
    )


def is_locked(end_state, hashlock):
    """True if the `hashlock` is known and the correspoding secret is not."""
    return hashlock in end_state.hashlocks_to_pendinglocks


def is_secret_known(end_state, hashlock):
    """True if the `hashlock` is for a lock with a known secret."""
    return hashlock in end_state.hashlocks_to_unclaimedlocks


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


def is_valid_mediatedtransfer(mediated_transfer, channel_state, sender_state, receiver_state):
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
        msg = 'Invalid MediatedTransfer message. Same lockhash handled twice.'
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
            msg = 'Invalid MediatedTransfer message. {}'.format(signature_msg)

            result = (False, msg, None)

        elif received_balance_proof.nonce != expected_nonce:
            # The nonces must increase sequentially, otherwise there is a
            # synchronization problem
            msg = (
                'Invalid MediatedTransfer message. '
                'Nonce did not change sequentially, expected: {} got: {}.'
            ).format(
                expected_nonce,
                received_balance_proof.nonce,
            )

            result = (False, msg, None)

        elif received_balance_proof.locksroot != locksroot_with_lock:
            # The locksroot must be updated to include the new lock
            msg = (
                "Invalid MediatedTransfer message. "
                "Balance proof's locksroot didn't match, expected: {} got: {}."
            ).format(
                hexlify(locksroot_with_lock).decode(),
                hexlify(received_balance_proof.locksroot).decode(),
            )

            result = (False, msg, None)

        elif received_balance_proof.transferred_amount != current_transferred_amount:
            # Mediated transfers must not change transferred_amount
            msg = (
                "Invalid MediatedTransfer message. "
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
                'Invalid MediatedTransfer message. '
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
                'Invalid MediatedTransfer message. '
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

    lock = get_lock(sender_state, unlock.hashlock)

    if lock is not None:
        new_merkletree = compute_merkletree_without(sender_state.merkletree, lock.lockhash)
        locksroot_without_lock = merkleroot(new_merkletree)

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
            hexlify(unlock.hashlock).decode(),
        )

        result = (False, msg, None)

    elif lock is None:
        msg = 'Invalid Secret message. There is no correspoding lock for {}'.format(
            hexlify(unlock.hashlock).decode(),
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
        result = (True, None, new_merkletree)

    return result


def get_amount_locked(end_state):
    total_pending = sum(
        lock.amount
        for lock in end_state.hashlocks_to_pendinglocks.values()
    )

    total_unclaimed = sum(
        unlock.lock.amount
        for unlock in end_state.hashlocks_to_unclaimedlocks.values()
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
        for partialproof in end_state.hashlocks_to_unclaimedlocks.values()
    ]


def get_lock(
        end_state: 'NettingChannelEndState',
        hashlock: typing.keccak256,
) -> HashTimeLockState:
    """Return the lock correspoding to `hashlock` or None if the lock is
    unknown.
    """
    lock = end_state.hashlocks_to_pendinglocks.get(hashlock)

    if not lock:
        partial_unlock = end_state.hashlocks_to_unclaimedlocks.get(hashlock)

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


def del_lock(end_state, hashlock):
    assert is_known(end_state, hashlock)

    if hashlock in end_state.hashlocks_to_pendinglocks:
        del end_state.hashlocks_to_pendinglocks[hashlock]

    if hashlock in end_state.hashlocks_to_unclaimedlocks:
        del end_state.hashlocks_to_unclaimedlocks[hashlock]


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
        secret: typing.secret,
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
        lockhash: typing.keccak256,
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


def create_senddirecttransfer(channel_state, amount, identifier):
    our_balance_proof = channel_state.our_state.balance_proof

    if our_balance_proof:
        transferred_amount = amount + our_balance_proof.transferred_amount
        locksroot = our_balance_proof.locksroot
    else:
        transferred_amount = amount
        locksroot = EMPTY_MERKLE_ROOT

    nonce = get_next_nonce(channel_state.our_state)
    token = channel_state.token_address
    recipient = channel_state.partner_state.address

    balance_proof = BalanceProofUnsignedState(
        nonce,
        transferred_amount,
        locksroot,
        channel_state.identifier,
    )

    direct_transfer = SendDirectTransfer(
        identifier,
        balance_proof,
        token,
        recipient,
    )

    return direct_transfer


def create_sendmediatedtransfer(
        channel_state,
        initiator,
        target,
        amount,
        identifier,
        expiration,
        hashlock):

    our_state = channel_state.our_state
    partner_state = channel_state.partner_state
    our_balance_proof = our_state.balance_proof

    # The caller must check the capacity prior to the call
    msg = 'caller must make sure there is enough balance'
    assert amount <= get_distributable(our_state, partner_state), msg

    lock = HashTimeLockState(
        amount,
        expiration,
        hashlock,
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
        identifier,
        token,
        balance_proof,
        lock,
        initiator,
        target,
    )

    mediatedtransfer = SendMediatedTransfer2(
        locked_transfer,
        recipient,
    )

    return mediatedtransfer, merkletree


def create_unlock(channel_state, identifier, secret, lock):
    msg = 'caller must make sure the lock is known'
    assert is_known(channel_state.our_state, lock.hashlock), msg

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

    unlock_lock = SendBalanceProof2(
        identifier,
        token,
        recipient,
        secret,
        balance_proof,
    )

    return unlock_lock, merkletree


def send_directtransfer(channel_state, amount, identifier):
    direct_transfer = create_senddirecttransfer(
        channel_state,
        amount,
        identifier,
    )

    channel_state.our_state.balance_proof = direct_transfer.balance_proof

    return direct_transfer


def send_mediatedtransfer(
        channel_state,
        initiator,
        target,
        amount,
        identifier,
        expiration,
        hashlock):

    send_event, merkletree = create_sendmediatedtransfer(
        channel_state,
        initiator,
        target,
        amount,
        identifier,
        expiration,
        hashlock,
    )

    transfer = send_event.transfer
    lock = transfer.lock
    channel_state.our_state.balance_proof = transfer.balance_proof
    channel_state.our_state.merkletree = merkletree
    channel_state.our_state.hashlocks_to_pendinglocks[lock.hashlock] = lock

    return send_event


def send_refundtransfer(
        channel_state,
        initiator,
        target,
        amount,
        identifier,
        expiration,
        hashlock):

    msg = 'Refunds are only valid for *know and pending* transfers'
    assert hashlock in channel_state.partner_state.hashlocks_to_pendinglocks, msg

    send_mediated_transfer, merkletree = create_sendmediatedtransfer(
        channel_state,
        initiator,
        target,
        amount,
        identifier,
        expiration,
        hashlock,
    )

    mediated_transfer = send_mediated_transfer.transfer
    lock = mediated_transfer.lock

    channel_state.our_state.balance_proof = mediated_transfer.balance_proof
    channel_state.our_state.merkletree = merkletree
    channel_state.our_state.hashlocks_to_pendinglocks[lock.hashlock] = lock

    refund_transfer = refund_from_sendmediated(send_mediated_transfer)
    return refund_transfer


def send_unlock(channel_state, identifier, secret, hashlock):
    lock = get_lock(channel_state.our_state, hashlock)
    assert lock

    unlock_lock, merkletree = create_unlock(
        channel_state,
        identifier,
        secret,
        lock,
    )

    channel_state.our_state.balance_proof = unlock_lock.balance_proof
    channel_state.our_state.merkletree = merkletree

    del_lock(channel_state.our_state, lock.hashlock)

    return unlock_lock


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


def register_secret_endstate(end_state, secret, hashlock):
    if is_locked(end_state, hashlock):
        pendinglock = end_state.hashlocks_to_pendinglocks[hashlock]
        del end_state.hashlocks_to_pendinglocks[hashlock]

        end_state.hashlocks_to_unclaimedlocks[hashlock] = UnlockPartialProofState(
            pendinglock,
            secret,
        )


def register_secret(channel_state, secret, hashlock):
    """This will register the secret and set the lock to the unlocked stated.

    Even though the lock is unlock it's is *not* claimed. The capacity will
    increase once the next balance proof is received.
    """
    our_state = channel_state.our_state
    partner_state = channel_state.partner_state

    register_secret_endstate(our_state, secret, hashlock)
    register_secret_endstate(partner_state, secret, hashlock)


def handle_send_directtransfer(channel_state, state_change):
    events = list()

    amount = state_change.amount
    identifier = state_change.identifier
    distributable_amount = get_distributable(channel_state.our_state, channel_state.partner_state)

    is_open = get_status(channel_state) == CHANNEL_STATE_OPENED
    is_valid = amount > 0
    can_pay = amount <= distributable_amount

    if is_open and is_valid and can_pay:
        direct_transfer = send_directtransfer(
            channel_state,
            amount,
            identifier,
        )
        events.append(direct_transfer)
    else:
        if not is_open:
            failure = EventTransferSentFailed(
                state_change.identifier,
                'Channel is not opened',
            )
            events.append(failure)

        elif not is_valid:
            msg = 'Transfer amount is invalid. Transfer: {}'.format(amount)

            failure = EventTransferSentFailed(state_change.identifier, msg)
            events.append(failure)

        elif not can_pay:
            msg = (
                'Transfer amount exceeds the available capacity. '
                'Capacity: {}, Transfer: {}'
            ).format(
                distributable_amount,
                amount,
            )

            failure = EventTransferSentFailed(state_change.identifier, msg)
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
        event = EventTransferReceivedSuccess(
            direct_transfer.transfer_identifier,
            transfer_amount,
            channel_state.partner_state.address,
        )
        events = [event]
    else:
        event = EventTransferReceivedInvalidDirectTransfer(
            direct_transfer.transfer_identifier,
            reason=msg,
        )
        events = [event]

    return TransitionResult(channel_state, events)


def handle_receive_mediatedtransfer(
        channel_state: 'NettingChannelState',
        mediated_transfer: 'LockedTransferState'):
    """Register the latest known transfer.

    The receiver needs to use this method to update the container with a
    _valid_ transfer, otherwise the locksroot will not contain the pending
    transfer. The receiver needs to ensure that the merkle root has the
    hashlock included, otherwise it won't be able to claim it.
    """
    is_valid, msg, merkletree = is_valid_mediatedtransfer(
        mediated_transfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )

    if is_valid:
        channel_state.partner_state.balance_proof = mediated_transfer.balance_proof
        channel_state.partner_state.merkletree = merkletree

        lock = mediated_transfer.lock
        channel_state.partner_state.hashlocks_to_pendinglocks[lock.hashlock] = lock

    return is_valid, msg


def handle_receive_refundtransfer(channel_state, refund_transfer):
    return handle_receive_mediatedtransfer(channel_state, refund_transfer)


def handle_receive_secretreveal(channel_state, state_change):
    secret = state_change.secret
    hashlock = state_change.hashlock

    register_secret(channel_state, secret, hashlock)


def handle_unlock(channel_state, unlock):
    is_valid, msg, unlocked_merkletree = is_valid_unlock(
        unlock,
        channel_state,
        channel_state.partner_state,
    )

    if is_valid:
        channel_state.partner_state.balance_proof = unlock.balance_proof
        channel_state.partner_state.merkletree = unlocked_merkletree

        del_lock(channel_state.partner_state, unlock.hashlock)

    return is_valid, msg


def handle_block(channel_state, state_change):
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


def handle_channel_newbalance(channel_state, state_change):
    events = list()
    participant_address = state_change.participant_address

    if participant_address == channel_state.our_state.address:
        new_balance = max(
            channel_state.our_state.contract_balance,
            state_change.contract_balance,
        )
        channel_state.our_state.contract_balance = new_balance

    elif participant_address == channel_state.partner_state.address:
        new_balance = max(
            channel_state.partner_state.contract_balance,
            state_change.contract_balance,
        )
        channel_state.partner_state.contract_balance = new_balance

    return TransitionResult(channel_state, events)


def handle_channel_withdraw(channel_state, state_change):
    hashlock = state_change.hashlock
    secret = state_change.secret

    our_withdraw = (
        state_change.receiver == channel_state.our_state.address and
        is_locked(channel_state.partner_state, hashlock)
    )
    # FIXME: must not remove the lock, otherwise a new unlock proof cannot be
    # made
    if our_withdraw:
        del_lock(channel_state.partner_state, hashlock)

    partner_withdraw = (
        state_change.receiver == channel_state.partner_state.address and
        is_locked(channel_state.our_state, hashlock)
    )
    if partner_withdraw:
        del_lock(channel_state.our_state, hashlock)

    # Withdraw is required if there was a refund in this channel, and the
    # secret is learned from the withdraw event.
    events = []
    if is_locked(channel_state.our_state, hashlock):
        lock = get_lock(channel_state.our_state, hashlock)
        proof = compute_proof_for_lock(channel_state.our_state, secret, lock)
        withdraw = ContractSendChannelWithdraw(channel_state.identifier, [proof])
        events.append(withdraw)

    register_secret(channel_state, secret, hashlock)

    return TransitionResult(channel_state, events)


def state_transition(channel_state, state_change, block_number):
    events = list()
    iteration = TransitionResult(channel_state, events)

    if isinstance(state_change, Block):
        iteration = handle_block(channel_state, state_change)

    elif isinstance(state_change, ActionChannelClose):
        iteration = handle_action_close(channel_state, state_change, block_number)

    elif isinstance(state_change, ActionTransferDirect):
        iteration = handle_send_directtransfer(channel_state, state_change)

    elif isinstance(state_change, ContractReceiveChannelClosed):
        iteration = handle_channel_closed(channel_state, state_change)

    elif isinstance(state_change, ContractReceiveChannelSettled):
        iteration = handle_channel_settled(channel_state, state_change)

    elif isinstance(state_change, ContractReceiveChannelNewBalance):
        iteration = handle_channel_newbalance(channel_state, state_change)

    elif isinstance(state_change, ContractReceiveChannelWithdraw):
        iteration = handle_channel_withdraw(channel_state, state_change)

    elif isinstance(state_change, ReceiveTransferDirect2):
        iteration = handle_receive_directtransfer(channel_state, state_change)

    return iteration
