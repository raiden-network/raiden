# pylint: disable=too-many-locals,too-many-statements,too-many-lines
import random
from hashlib import sha256
from itertools import cycle

from eth_utils import keccak

from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX
from raiden.messages.decode import balanceproof_from_envelope
from raiden.messages.transfers import Unlock
from raiden.tests.unit.channel_state.utils import (
    assert_partner_state,
    create_channel_from_models,
    create_model,
)
from raiden.tests.utils.factories import UNIT_CHAIN_ID, make_address, make_secret
from raiden.tests.utils.transfer import make_receive_expired_lock, make_receive_transfer_mediated
from raiden.transfer import channel
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.state import (
    HashTimeLockState,
    NettingChannelEndState,
    PendingLocksState,
    RouteState,
    UnlockPartialProofState,
    make_empty_pending_locks_state,
)
from raiden.transfer.state_change import ReceiveUnlock
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import LockedAmount


def test_get_amount_locked():
    state = NettingChannelEndState(address=make_address(), contract_balance=0)

    assert channel.get_amount_locked(state) == 0

    secrethash = sha256(make_secret(1)).digest()
    state.secrethashes_to_lockedlocks[secrethash] = HashTimeLockState(
        amount=23, expiration=100, secrethash=secrethash
    )
    assert channel.get_amount_locked(state) == 23

    secret = make_secret(1)
    secrethash = sha256_secrethash(secret)
    lock = HashTimeLockState(amount=21, expiration=100, secrethash=secrethash)
    state.secrethashes_to_unlockedlocks[secrethash] = UnlockPartialProofState(
        lock=lock, secret=secret
    )
    assert channel.get_amount_locked(state) == 44

    secret = make_secret(2)
    secrethash = sha256_secrethash(secret)
    lock = HashTimeLockState(amount=19, expiration=100, secrethash=secrethash)
    state.secrethashes_to_onchain_unlockedlocks[secrethash] = UnlockPartialProofState(
        lock=lock, secret=secret
    )
    assert channel.get_amount_locked(state) == 63


def test_interwoven_transfers():
    """Can keep doing transactions even if not all secrets have been released."""
    number_of_transfers = 100
    balance_for_all_transfers = 11 * number_of_transfers

    lock_amounts = cycle([1, 3, 5, 7, 11])
    lock_secrets = [make_secret(i) for i in range(number_of_transfers)]

    our_model, _ = create_model(70)
    partner_model, privkey2 = create_model(balance_for_all_transfers)
    signer2 = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model, partner_model, privkey2)

    block_number = 1000
    nonce = 0
    transferred_amount = 0
    locked_amount = 0
    our_model_current = our_model
    partner_model_current = partner_model
    token_network_address = channel_state.token_network_address

    for i, (lock_amount, lock_secret) in enumerate(zip(lock_amounts, lock_secrets)):
        nonce += 1
        block_number += 1
        locked_amount += lock_amount

        lock_expiration = block_number + channel_state.settle_timeout - 1
        lock_secrethash = sha256(lock_secret).digest()
        lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

        pending_locks = PendingLocksState(list(partner_model_current.pending_locks))
        pending_locks.locks.append(bytes(lock.encoded))

        partner_model_current = partner_model_current._replace(
            distributable=partner_model_current.distributable - lock_amount,
            amount_locked=partner_model_current.amount_locked + lock_amount,
            next_nonce=partner_model_current.next_nonce + 1,
            pending_locks=pending_locks.locks,
        )

        receive_lockedtransfer = make_receive_transfer_mediated(
            channel_state,
            privkey2,
            nonce,
            transferred_amount,
            lock,
            pending_locks=pending_locks,
            locked_amount=locked_amount,
        )

        is_valid, _, msg = channel.handle_receive_lockedtransfer(
            channel_state, receive_lockedtransfer
        )
        assert is_valid, msg

        assert_partner_state(
            channel_state.our_state, channel_state.partner_state, our_model_current
        )
        assert_partner_state(
            channel_state.partner_state, channel_state.our_state, partner_model_current
        )

        # claim a transaction at every other iteration, leaving the current one
        # in place
        if i % 2:
            # Update our model:
            # - Increase nonce because the secret is a new balance proof
            # - The lock is removed from the pending locks, the balance proof must be updated
            #   - The locksroot must have unlocked lock removed
            #   - The transferred amount must be increased by the lock amount
            # - This changes the balance for both participants:
            #   - the sender balance and locked amount is decremented by the lock amount
            #   - the receiver balance and distributable is incremented by the lock amount
            nonce += 1
            transferred_amount += lock_amount
            locked_amount -= lock_amount

            pending_locks = list(partner_model_current.pending_locks)
            pending_locks.remove(bytes(lock.encoded))
            locksroot = compute_locksroot(PendingLocksState(pending_locks))

            partner_model_current = partner_model_current._replace(
                amount_locked=partner_model_current.amount_locked - lock_amount,
                balance=partner_model_current.balance - lock_amount,
                next_nonce=partner_model_current.next_nonce + 1,
                pending_locks=pending_locks,
            )

            our_model_current = our_model_current._replace(
                balance=our_model_current.balance + lock_amount,
                distributable=our_model_current.distributable + lock_amount,
            )

            message_identifier = random.randint(0, UINT64_MAX)
            unlock_message = Unlock(
                chain_id=UNIT_CHAIN_ID,
                message_identifier=message_identifier,
                payment_identifier=nonce,
                nonce=nonce,
                token_network_address=token_network_address,
                channel_identifier=channel_state.identifier,
                transferred_amount=transferred_amount,
                locked_amount=locked_amount,
                locksroot=locksroot,
                secret=lock_secret,
                signature=EMPTY_SIGNATURE,
            )
            unlock_message.sign(signer2)

            balance_proof = balanceproof_from_envelope(unlock_message)
            unlock_state_change = ReceiveUnlock(
                message_identifier=random.randint(0, UINT64_MAX),
                secret=lock_secret,
                balance_proof=balance_proof,
                sender=balance_proof.sender,
            )

            is_valid, _, msg = channel.handle_unlock(channel_state, unlock_state_change)
            assert is_valid, msg

            assert_partner_state(
                channel_state.our_state, channel_state.partner_state, our_model_current
            )
            assert_partner_state(
                channel_state.partner_state, channel_state.our_state, partner_model_current
            )


def test_channel_never_expires_lock_with_secret_onchain():
    """Send a mediated transfer and register secret on chain.
    The lock must be moved into secrethashes_to_onchain_unlockedlocks
    """
    our_model1, _ = create_model(70)
    partner_model1, partner_key1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_key1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()

    lock = HashTimeLockState(
        amount=lock_amount, expiration=lock_expiration, secrethash=lock_secrethash
    )

    payment_identifier = 1
    secret = None
    message_identifier = random.randint(0, UINT64_MAX)
    transfer_target = make_address()
    transfer_initiator = make_address()

    channel.send_lockedtransfer(
        channel_state=channel_state,
        initiator=transfer_initiator,
        target=transfer_target,
        secret=secret,
        amount=lock_amount,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        expiration=lock_expiration,
        secrethash=lock_secrethash,
        route_states=[
            RouteState(
                # pylint: disable=E1101
                route=[channel_state.partner_state.address],
            )
        ],
    )

    # pylint: disable=E1101
    assert lock.secrethash in channel_state.our_state.secrethashes_to_lockedlocks

    channel.register_onchain_secret(
        channel_state=channel_state,
        secret=lock_secret,
        secrethash=lock.secrethash,
        secret_reveal_block_number=lock_expiration - 1,
        delete_lock=True,
    )

    # pylint: disable=E1101
    assert lock.secrethash not in channel_state.our_state.secrethashes_to_lockedlocks
    # pylint: disable=E1101
    assert lock.secrethash in channel_state.our_state.secrethashes_to_onchain_unlockedlocks


def test_regression_must_update_balanceproof_remove_expired_lock():
    """A remove expire lock message contains a balance proof and changes the
    pending locks, the receiver must update the channel state.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    block_number = 100

    lock_amount = 10
    lock_expiration = block_number - 10
    lock_secret = keccak(b"test_regression_must_update_balanceproof_remove_expired_lock")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(
        amount=lock_amount, expiration=lock_expiration, secrethash=lock_secrethash
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state=channel_state,
        privkey=privkey2,
        nonce=nonce,
        transferred_amount=transferred_amount,
        lock=lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state=channel_state, mediated_transfer=receive_lockedtransfer
    )
    assert is_valid, msg

    # pylint: disable=E1101
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_lockedlocks

    lock_expired = make_receive_expired_lock(
        channel_state=channel_state,
        privkey=privkey2,
        nonce=receive_lockedtransfer.balance_proof.nonce + 1,
        transferred_amount=transferred_amount,
        lock=lock,
        locked_amount=LockedAmount(0),
    )

    is_valid, msg, _ = channel.is_valid_lock_expired(
        state_change=lock_expired,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
        receiver_state=channel_state.our_state,
        block_number=block_number,
    )

    assert is_valid, msg

    iteration = channel.handle_receive_lock_expired(
        channel_state=channel_state, state_change=lock_expired, block_number=block_number
    )

    new_channel_state = iteration.new_state
    assert lock.secrethash not in new_channel_state.partner_state.secrethashes_to_lockedlocks
    msg = "the balance proof must be updated"
    assert new_channel_state.partner_state.balance_proof == lock_expired.balance_proof, msg
    assert new_channel_state.partner_state.pending_locks == make_empty_pending_locks_state()


def test_channel_must_ignore_remove_expired_locks_if_secret_registered_onchain():
    """Remove expired lock messages must be ignored if the lock was unlocked
    on-chain.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    block_number = 100

    lock_amount = 10
    lock_expiration = block_number - 10
    lock_secret = keccak(
        b"test_channel_must_ignore_remove_expired_locks_if_secret_registered_onchain"
    )
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(
        amount=lock_amount, expiration=lock_expiration, secrethash=lock_secrethash
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state=channel_state,
        privkey=privkey2,
        nonce=nonce,
        transferred_amount=transferred_amount,
        lock=lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state=channel_state, mediated_transfer=receive_lockedtransfer
    )
    assert is_valid, msg

    # pylint: disable=E1101
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_lockedlocks

    channel.register_onchain_secret(
        channel_state=channel_state,
        secret=lock_secret,
        secrethash=lock_secrethash,
        secret_reveal_block_number=1,
        delete_lock=False,
    )

    lock_expired = ReceiveLockExpired(
        balance_proof=receive_lockedtransfer.balance_proof,
        sender=receive_lockedtransfer.balance_proof.sender,
        secrethash=lock_secrethash,
        message_identifier=1,
    )

    is_valid, msg, _ = channel.is_valid_lock_expired(
        state_change=lock_expired,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
        receiver_state=channel_state.our_state,
        block_number=block_number,
    )

    assert not is_valid
    assert "on-chain" in msg, "message must inform the lock was unlocked on-chain"

    channel.handle_receive_lock_expired(
        channel_state=channel_state, state_change=lock_expired, block_number=block_number
    )

    # pylint: disable=E1101
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_lockedlocks


def test_channel_must_accept_expired_locks():
    """A node may go offline for an undetermined period of time, and when it
    comes back online it must accept the messages that are waiting, otherwise
    the partner node won't make progress with its queue.

    If a N node goes offline for a number B of blocks, and the partner does not
    close the channel, when N comes back online some of the messages from its
    partner may become expired. Nevertheless these messages are ordered and must
    be accepted for the partner to make progress with its queue.

    Note: Accepting a message with an expired lock does *not* imply the token
    transfer happened, and the receiver node must *not* forward the transfer,
    only accept the message allowing the partner to progress with its message
    queue.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    block_number = 100

    lock_amount = 10
    lock_expiration = block_number - 10
    lock_secrethash = sha256(b"test_channel_must_accept_expired_locks").digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state, privkey2, nonce, transferred_amount, lock
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)
    assert is_valid, msg

    # the locked amount must increase even though the lock is expired, this
    # will be removed by an additional synchronization message from the partner
    our_model2 = our_model1
    partner_model2 = partner_model1._replace(
        amount_locked=lock_amount,
        distributable=partner_model1.distributable - lock_amount,
        next_nonce=partner_model1.next_nonce + 1,
        pending_locks=[bytes(lock.encoded)],
    )

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)


def test_channel_rejects_onchain_secret_reveal_with_expired_locks():
    """Ensure that on-chain secret registration becomes a noop
    if the lock has already expired.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    # On-Chain secret registration happens between
    # Lock expiration & Lock expiration + required confirmation
    block_number = 100
    lock_expiration = block_number - 10
    secret_reveal_block_number = block_number - 5

    lock_amount = 10
    lock_secret = keccak(b"test_channel_rejects_onchain_secret_reveal_with_expired_locks")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(
        amount=lock_amount, expiration=lock_expiration, secrethash=lock_secrethash
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state=channel_state,
        privkey=privkey2,
        nonce=nonce,
        transferred_amount=transferred_amount,
        lock=lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state=channel_state, mediated_transfer=receive_lockedtransfer
    )
    assert is_valid, msg

    # pylint: disable=E1101
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_lockedlocks

    # If secret registration happens after the lock has expired, then NOOP
    channel.register_onchain_secret(
        channel_state=channel_state,
        secret=lock_secret,
        secrethash=lock_secrethash,
        secret_reveal_block_number=secret_reveal_block_number,
        delete_lock=False,
    )

    # pylint: disable=E1101
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_lockedlocks
    assert {} == channel_state.partner_state.secrethashes_to_onchain_unlockedlocks

    # If it happens before, the lockedlock is unlocked
    channel.register_onchain_secret(
        channel_state=channel_state,
        secret=lock_secret,
        secrethash=lock_secrethash,
        secret_reveal_block_number=lock_expiration - 1,
        delete_lock=True,
    )

    # pylint: disable=E1101
    assert lock.secrethash not in channel_state.partner_state.secrethashes_to_lockedlocks
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_onchain_unlockedlocks


def test_valid_lock_expired_for_unlocked_lock():
    """This tests that locked and unlocked locks behave the same when
    they are checked with `is_valid_lock_expired`.
    This tests issue #2828
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    block_number = 100

    lock_amount = 10
    lock_expiration = block_number - 10
    lock_secret = keccak(b"test_valid_lock_expired_for_unlocked_lock")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(
        amount=lock_amount, expiration=lock_expiration, secrethash=lock_secrethash
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state=channel_state,
        privkey=privkey2,
        nonce=nonce,
        transferred_amount=transferred_amount,
        lock=lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state=channel_state, mediated_transfer=receive_lockedtransfer
    )
    assert is_valid, msg

    # pylint: disable=E1101
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_lockedlocks

    channel.register_offchain_secret(
        channel_state=channel_state, secret=lock_secret, secrethash=lock_secrethash
    )

    lock_expired = ReceiveLockExpired(
        balance_proof=receive_lockedtransfer.balance_proof,
        sender=receive_lockedtransfer.balance_proof.sender,
        secrethash=lock_secrethash,
        message_identifier=1,
    )

    is_valid, _, _ = channel.is_valid_lock_expired(
        state_change=lock_expired,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
        receiver_state=channel_state.our_state,
        block_number=block_number,
    )

    assert not is_valid
    # pylint: disable=E1101
    assert lock.secrethash in channel_state.partner_state.secrethashes_to_unlockedlocks
