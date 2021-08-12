# pylint: disable=too-many-locals,too-many-statements,too-many-lines
import random
from hashlib import sha256

from eth_utils import keccak

from raiden.constants import EMPTY_SIGNATURE, LOCKSROOT_OF_NO_LOCKS, UINT64_MAX
from raiden.messages.decode import balanceproof_from_envelope
from raiden.messages.transfers import Unlock
from raiden.tests.unit.channel_state.utils import (
    assert_partner_state,
    create_channel_from_models,
    create_model,
)
from raiden.tests.utils.factories import (
    UNIT_CHAIN_ID,
    TransactionExecutionStatusProperties,
    create,
    make_address,
)
from raiden.tests.utils.transfer import make_receive_transfer_mediated
from raiden.transfer import channel
from raiden.transfer.state import HashTimeLockState, PendingLocksState, RouteState
from raiden.transfer.state_change import ReceiveUnlock
from raiden.utils.signer import LocalSigner


def test_receive_lockedtransfer_before_deposit():
    """Regression test that ensures we accept incoming mediated transfers, even if we don't have
    any balance on the channel.
    """
    our_model1, _ = create_model(0)  # our deposit is 0
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state, privkey2, nonce, transferred_amount, lock
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)

    # this node partner has enough balance, the transfer must be accepted
    assert is_valid, msg


def test_channelstate_send_lockedtransfer():
    """Sending a mediated transfer must update the participant state.

    This tests only the state of the sending node, without synchronisation.
    """
    our_model1, _ = create_model(70)
    partner_model1, partner_key1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_key1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()
    secret = None

    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    payment_identifier = 1
    message_identifier = random.randint(0, UINT64_MAX)
    transfer_target = make_address()
    transfer_initiator = make_address()

    channel.send_lockedtransfer(
        channel_state,
        transfer_initiator,
        transfer_target,
        lock_amount,
        message_identifier,
        payment_identifier,
        lock_expiration,
        secret,
        lock_secrethash,
        route_states=[
            RouteState(
                # pylint: disable=E1101
                route=[channel_state.partner_state.address],
            )
        ],
    )

    our_model2 = our_model1._replace(
        distributable=our_model1.distributable - lock_amount,
        amount_locked=lock_amount,
        next_nonce=2,
        pending_locks=[bytes(lock.encoded)],
    )
    partner_model2 = partner_model1

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)


def test_channelstate_receive_lockedtransfer():
    """Tests receiving a mediated transfer.

    The transfer is done in three steps:
        - a mediated transfer including a lock in its balance proof is sent
        - the secret is revealed
        - the unlocked balance proof is sent updating the transferred_amount
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    signer2 = LocalSigner(privkey2)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    # Step 1: Simulate receiving a transfer
    # - The receiver end state doesnt change
    # - The lock must be registered with the sender end
    lock_amount = 30
    lock_expiration = 10
    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state, privkey2, nonce, transferred_amount, lock
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)
    assert is_valid, msg

    our_model2 = our_model1
    partner_model2 = partner_model1._replace(
        distributable=partner_model1.distributable - lock_amount,
        amount_locked=lock_amount,
        next_nonce=2,
        pending_locks=[bytes(lock.encoded)],
    )
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)

    # Step 2: Simulate learning the secret
    # - Registers the secret, this must not change the balance/locked amount
    channel.register_offchain_secret(channel_state, lock_secret, lock_secrethash)

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)

    # Step 3: Simulate unlocking the lock
    # - Update the balances
    transferred_amount = 0
    message_identifier = random.randint(0, UINT64_MAX)
    token_network_address = channel_state.token_network_address
    unlock_message = Unlock(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=1,
        nonce=2,
        token_network_address=token_network_address,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount + lock_amount,
        locked_amount=0,
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        secret=lock_secret,
        signature=EMPTY_SIGNATURE,
    )
    unlock_message.sign(signer2)
    # Let's also create an invalid secret to test unlock with invalid chain id
    invalid_unlock_message = Unlock(
        chain_id=UNIT_CHAIN_ID + 1,
        message_identifier=message_identifier,
        payment_identifier=1,
        nonce=2,
        token_network_address=token_network_address,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount + lock_amount,
        locked_amount=0,
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        secret=lock_secret,
        signature=EMPTY_SIGNATURE,
    )
    invalid_unlock_message.sign(signer2)

    balance_proof = balanceproof_from_envelope(unlock_message)
    unlock_state_change = ReceiveUnlock(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=lock_secret,
        balance_proof=balance_proof,
        sender=balance_proof.sender,
    )

    # First test that unlock with invalid chain_id fails
    invalid_balance_proof = balanceproof_from_envelope(invalid_unlock_message)
    invalid_unlock_state_change = ReceiveUnlock(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=lock_secret,
        balance_proof=invalid_balance_proof,
        sender=invalid_balance_proof.sender,
    )
    is_valid, _, _ = channel.handle_unlock(channel_state, invalid_unlock_state_change)
    assert not is_valid, "Unlock message with chain_id different than the channel's should fail"

    is_valid, _, msg = channel.handle_unlock(channel_state, unlock_state_change)
    assert is_valid, msg

    our_model3 = our_model2._replace(
        balance=our_model2.balance + lock_amount, distributable=our_model2.balance + lock_amount
    )
    partner_model3 = partner_model2._replace(
        balance=partner_model2.balance - lock_amount,
        amount_locked=0,
        next_nonce=3,
        pending_locks=[],
    )

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model3)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model3)

    # receive lockedtransfer for a closed channel
    channel_state.close_transaction = create(
        TransactionExecutionStatusProperties(finished_block_number=2)
    )
    is_valid, _, _ = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)
    assert not is_valid


def test_channelstate_lockedtransfer_overspent():
    """Receiving a lock with an amount large than distributable must be
    ignored.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)

    lock_amount = distributable + 1
    lock_expiration = 10
    lock_secrethash = sha256(b"test_channelstate_lockedtransfer_overspent").digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state, privkey2, nonce, transferred_amount, lock
    )

    is_valid, _, _ = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)
    assert not is_valid, "message is invalid because it is spending more than the distributable"

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_lockedtransfer_invalid_chainid():
    """Receiving a locked transfer with chain_id different from the channel's
    chain_id should be ignored
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)

    lock_amount = distributable - 1
    lock_expiration = 10
    lock_secrethash = sha256(b"test_channelstate_lockedtransfer_overspent").digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state, privkey2, nonce, transferred_amount, lock, chain_id=UNIT_CHAIN_ID + 1
    )

    is_valid, _, _ = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)
    assert not is_valid, "message is invalid because it uses different chain_id than the channel"

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_lockedtransfer_overspend_with_multiple_pending_transfers():
    """Receiving a concurrent lock with an amount large than distributable
    must be ignored.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    # Step 1: Create a lock with an amount of 1
    # - this wont be unlocked
    lock1_amount = 1
    lock1_expiration = 1 + channel_state.settle_timeout
    lock1_secrethash = sha256(
        b"test_receive_cannot_overspend_with_multiple_pending_transfers1"
    ).digest()
    lock1 = HashTimeLockState(lock1_amount, lock1_expiration, lock1_secrethash)

    nonce1 = 1
    transferred_amount = 0
    receive_lockedtransfer1 = make_receive_transfer_mediated(
        channel_state, privkey2, nonce1, transferred_amount, lock1
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state, receive_lockedtransfer1
    )
    assert is_valid, msg

    our_model2 = our_model1
    partner_model2 = partner_model1._replace(
        distributable=partner_model1.distributable - lock1.amount,
        amount_locked=lock1.amount,
        next_nonce=2,
        pending_locks=[bytes(lock1.encoded)],
    )

    # The valid transfer is handled normally
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)

    # Step 2: Create a lock with the current *distributable + 1*
    # - This must be ignored
    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)
    lock2_amount = distributable + 1
    lock2_expiration = channel_state.settle_timeout
    lock2_secrethash = sha256(
        b"test_receive_cannot_overspend_with_multiple_pending_transfers2"
    ).digest()
    lock2 = HashTimeLockState(lock2_amount, lock2_expiration, lock2_secrethash)
    locks = PendingLocksState([bytes(lock1.encoded), bytes(lock2.encoded)])

    nonce2 = 2
    receive_lockedtransfer2 = make_receive_transfer_mediated(
        channel_state, privkey2, nonce2, transferred_amount, lock2, pending_locks=locks
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state, receive_lockedtransfer2
    )
    assert not is_valid, "message is invalid because its expending more than the distributable"

    # The overspending transfer must be ignored
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)
