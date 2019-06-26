import random
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256

from raiden.constants import LOCKSROOT_OF_NO_LOCKS, MAXIMUM_PENDING_TRANSFERS
from raiden.tests.unit.test_channelstate import (
    create_channel_from_models,
    create_model,
    make_receive_transfer_mediated,
)
from raiden.tests.utils import factories
from raiden.tests.utils.factories import make_block_hash, make_transaction_hash
from raiden.transfer import channel
from raiden.transfer.channel import (
    compute_locksroot,
    get_batch_unlock_gain,
    get_secret,
    get_status,
    handle_action_update_fee,
    handle_block,
    handle_receive_lockedtransfer,
    is_balance_proof_usable_onchain,
    is_valid_balanceproof_signature,
    set_settled,
)
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
    HashTimeLockState,
    PendingLocksState,
    TransactionExecutionStatus,
    UnlockPartialProofState,
)
from raiden.transfer.state_change import (
    ActionChannelUpdateFee,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelSettled,
)
from raiden.utils import sha3


def _channel_and_transfer(num_pending_locks):
    our_model, _ = create_model(700)
    partner_model, privkey = create_model(700, num_pending_locks)
    reverse_channel_state = create_channel_from_models(partner_model, our_model, privkey)

    lock_secret = sha3(b"some secret seed")
    lock = HashTimeLockState(30, 10, sha256(lock_secret).digest())

    mediated_transfer = make_receive_transfer_mediated(
        reverse_channel_state,
        privkey,
        nonce=partner_model.next_nonce,
        transferred_amount=0,
        lock=lock,
        pending_locks=PendingLocksState(partner_model.pending_locks + [bytes(lock.encoded)]),
        locked_amount=lock.amount,
    )

    channel_state = deepcopy(reverse_channel_state)
    channel_state.our_state = reverse_channel_state.partner_state
    channel_state.partner_state = reverse_channel_state.our_state

    return channel_state, mediated_transfer


def test_handle_receive_lockedtransfer_enforces_transfer_limit():

    state, transfer = _channel_and_transfer(num_pending_locks=MAXIMUM_PENDING_TRANSFERS - 1)
    is_valid, _, msg = channel.handle_receive_lockedtransfer(state, transfer)
    assert is_valid, msg

    state, transfer = _channel_and_transfer(num_pending_locks=MAXIMUM_PENDING_TRANSFERS)
    is_valid, _, _ = handle_receive_lockedtransfer(state, transfer)
    assert not is_valid


def test_channel_cleared_after_two_unlocks():
    our_model, _ = create_model(balance=700, num_pending_locks=1)
    partner_model, partner_key1 = create_model(balance=700, num_pending_locks=1)
    channel_state = create_channel_from_models(our_model, partner_model, partner_key1)
    block_number = 1
    block_hash = make_block_hash()
    pseudo_random_generator = random.Random()

    def make_unlock(unlock_end, partner_end):
        batch_unlock = ContractReceiveChannelBatchUnlock(
            transaction_hash=make_transaction_hash(),
            canonical_identifier=channel_state.canonical_identifier,
            receiver=partner_end.address,
            sender=unlock_end.address,
            locksroot=unlock_end.balance_proof.locksroot,
            unlocked_amount=10,
            returned_tokens=0,
            block_number=block_number,
            block_hash=block_hash,
        )
        return batch_unlock

    settle_channel = ContractReceiveChannelSettled(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        our_onchain_locksroot=compute_locksroot(channel_state.our_state.pending_locks),
        partner_onchain_locksroot=compute_locksroot(channel_state.partner_state.pending_locks),
        block_number=1,
        block_hash=make_block_hash(),
    )
    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=settle_channel,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    msg = "both participants have pending locks, locksroot must not represent the empty list"
    assert iteration.new_state.our_state.onchain_locksroot != LOCKSROOT_OF_NO_LOCKS, msg
    assert iteration.new_state.partner_state.onchain_locksroot != LOCKSROOT_OF_NO_LOCKS, msg

    batch_unlock = make_unlock(channel_state.our_state, channel_state.partner_state)
    iteration = channel.state_transition(
        channel_state=iteration.new_state,
        state_change=batch_unlock,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )
    msg = "all of our locks has been unlocked, onchain state must be updated"
    assert iteration.new_state.our_state.onchain_locksroot is LOCKSROOT_OF_NO_LOCKS, msg
    msg = "partner has pending locks, the locksroot must not represent the empty list"
    assert iteration.new_state.partner_state.onchain_locksroot is not LOCKSROOT_OF_NO_LOCKS, msg
    msg = "partner locksroot is not unlocked, channel should not have been cleaned"
    assert iteration.new_state is not None, msg

    # processing the same unlock twice must not count
    iteration = channel.state_transition(
        channel_state=iteration.new_state,
        state_change=batch_unlock,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )
    msg = "partner has pending locks, the locksroot must not represent the empty list"
    assert iteration.new_state.partner_state.onchain_locksroot is not LOCKSROOT_OF_NO_LOCKS, msg
    msg = "partner locksroot is not unlocked, channel should not have been cleaned"
    assert iteration.new_state is not None, msg

    iteration = channel.state_transition(
        channel_state=iteration.new_state,
        state_change=make_unlock(channel_state.partner_state, channel_state.our_state),
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )
    msg = "all unlocks have been done, channel must be cleared"
    assert iteration.new_state is None, msg


def test_channel_cleared_after_our_unlock():
    pseudo_random_generator = random.Random()
    our_model, _ = create_model(balance=700, num_pending_locks=1)
    partner_model, partner_key1 = create_model(balance=700, num_pending_locks=0)
    channel_state = create_channel_from_models(our_model, partner_model, partner_key1)
    block_number = 1
    block_hash = make_block_hash()

    def make_unlock(unlock_end, partner_end):
        batch_unlock = ContractReceiveChannelBatchUnlock(
            transaction_hash=make_transaction_hash(),
            canonical_identifier=channel_state.canonical_identifier,
            receiver=partner_end.address,
            sender=unlock_end.address,
            locksroot=unlock_end.balance_proof.locksroot,
            unlocked_amount=10,
            returned_tokens=0,
            block_number=block_number,
            block_hash=block_hash,
        )
        return batch_unlock

    settle_channel = ContractReceiveChannelSettled(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        our_onchain_locksroot=compute_locksroot(channel_state.our_state.pending_locks),
        partner_onchain_locksroot=compute_locksroot(channel_state.partner_state.pending_locks),
        block_number=1,
        block_hash=make_block_hash(),
    )

    assert settle_channel.our_onchain_locksroot != LOCKSROOT_OF_NO_LOCKS
    assert settle_channel.partner_onchain_locksroot == LOCKSROOT_OF_NO_LOCKS

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=settle_channel,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    batch_unlock = make_unlock(channel_state.our_state, channel_state.partner_state)
    iteration = channel.state_transition(
        channel_state=iteration.new_state,
        state_change=batch_unlock,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )
    msg = "partner did not have any locks in the pending locks, channel should have been cleaned"
    assert iteration.new_state is None, msg


def test_is_balance_proof_usable_onchain_answer_is_false():
    channel_state = factories.make_channel_set(number_of_channels=1).channels[0]
    balance_proof_wrong_channel = factories.create(factories.BalanceProofSignedStateProperties())
    result, msg = is_balance_proof_usable_onchain(
        received_balance_proof=balance_proof_wrong_channel,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
    )
    assert result is False, result
    assert msg.startswith("channel_identifier does not match. "), msg

    wrong_token_network_canonical_identifier = replace(
        channel_state.canonical_identifier, token_network_address=factories.make_address()
    )

    balance_proof_wrong_token_network = factories.create(
        factories.BalanceProofSignedStateProperties(
            canonical_identifier=wrong_token_network_canonical_identifier
        )
    )
    result, msg = is_balance_proof_usable_onchain(
        received_balance_proof=balance_proof_wrong_token_network,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
    )
    assert result is False, result
    assert msg.startswith("token_network_address does not match. "), msg

    balance_proof_overflow = factories.create(
        factories.BalanceProofSignedStateProperties(
            transferred_amount=factories.UINT256_MAX,
            locked_amount=1,
            canonical_identifier=channel_state.canonical_identifier,
        )
    )
    result, msg = is_balance_proof_usable_onchain(
        received_balance_proof=balance_proof_overflow,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
    )
    assert result is False, result
    assert msg.startswith("Balance proof total transferred amount would overflow "), msg
    assert str(factories.UINT256_MAX) in msg, msg
    assert str(factories.UINT256_MAX + 1) in msg, msg


def test_is_valid_balanceproof_signature():
    balance_proof = factories.create(factories.BalanceProofSignedStateProperties())
    valid, _ = is_valid_balanceproof_signature(balance_proof, factories.make_address())
    assert not valid, "Address does not match."

    balance_proof = factories.create(
        factories.BalanceProofSignedStateProperties(signature=b"\0" * 65)
    )
    valid, _ = is_valid_balanceproof_signature(balance_proof, factories.make_address())
    assert not valid, "Invalid signature."


def test_get_secret():
    secret1 = factories.make_secret()
    secret2 = factories.make_secret()
    secrethash3 = factories.make_keccak_hash()
    secrethash4 = factories.make_keccak_hash()

    lock_state = HashTimeLockState(amount=10, expiration=10, secrethash=factories.UNIT_SECRETHASH)
    end_state = factories.create(factories.NettingChannelEndStateProperties())
    end_state = factories.replace(
        end_state,
        secrethashes_to_lockedlocks={secrethash3: lock_state},
        secrethashes_to_unlockedlocks={
            sha3(secret1): UnlockPartialProofState(lock=lock_state, secret=secret1)
        },
        secrethashes_to_onchain_unlockedlocks={
            sha3(secret2): UnlockPartialProofState(lock=lock_state, secret=secret2)
        },
    )

    assert get_secret(end_state, sha3(secret1)) == secret1  # known secret from offchain unlock
    assert get_secret(end_state, sha3(secret2)) == secret2  # known secret from offchain unlock
    assert get_secret(end_state, secrethash3) is None  # known lock but not unlocked yet
    assert get_secret(end_state, secrethash4) is None  # unknown secrethash


def test_get_status():
    failed_status = TransactionExecutionStatus(
        finished_block_number=10, result=TransactionExecutionStatus.FAILURE
    )

    close_failed = factories.create(
        factories.NettingChannelStateProperties(close_transaction=failed_status)
    )
    assert get_status(close_failed) == CHANNEL_STATE_UNUSABLE

    settle_failed = factories.create(
        factories.NettingChannelStateProperties(settle_transaction=failed_status)
    )
    assert get_status(settle_failed) == CHANNEL_STATE_UNUSABLE


def test_set_settled():
    channel = factories.create(
        factories.NettingChannelStateProperties(
            settle_transaction=TransactionExecutionStatus(finished_block_number=None, result=None)
        )
    )

    assert get_status(channel) == CHANNEL_STATE_SETTLING
    set_settled(channel, block_number=100)
    assert get_status(channel) == CHANNEL_STATE_SETTLED


def test_handle_action_set_fee():
    state = factories.create(factories.NettingChannelStateProperties())
    flat_fee = 130
    proportional_fee = 1000
    action = ActionChannelUpdateFee(
        canonical_identifier=state.canonical_identifier,
        flat_fee=flat_fee,
        proportional_fee=proportional_fee,
        use_imbalance_penalty=False,
    )
    result = handle_action_update_fee(state, action)
    assert result.new_state.fee_schedule.flat == flat_fee
    assert result.new_state.fee_schedule.proportional == proportional_fee
    assert not result.new_state.fee_schedule.imbalance_penalty
    assert not result.events


def make_hash_time_lock_state(amount) -> HashTimeLockState:
    return HashTimeLockState(amount=amount, expiration=5, secrethash=factories.UNIT_SECRETHASH)


def make_unlock_partial_proof_state(amount):
    return UnlockPartialProofState(
        lock=make_hash_time_lock_state(amount), secret=factories.UNIT_SECRET
    )


def test_get_batch_unlock_gain():
    channel_state = factories.create(factories.NettingChannelStateProperties())
    channel_state.our_state = replace(
        channel_state.our_state,
        secrethashes_to_lockedlocks={
            factories.make_keccak_hash(): make_hash_time_lock_state(1),
            factories.make_keccak_hash(): make_hash_time_lock_state(2),
        },
        secrethashes_to_unlockedlocks={
            factories.make_keccak_hash(): make_unlock_partial_proof_state(4)
        },
        secrethashes_to_onchain_unlockedlocks={
            factories.make_keccak_hash(): make_unlock_partial_proof_state(8)
        },
    )
    channel_state.partner_state = replace(
        channel_state.partner_state,
        secrethashes_to_lockedlocks={factories.make_keccak_hash(): make_hash_time_lock_state(16)},
        secrethashes_to_unlockedlocks={
            factories.make_keccak_hash(): make_unlock_partial_proof_state(32)
        },
        secrethashes_to_onchain_unlockedlocks={
            factories.make_keccak_hash(): make_unlock_partial_proof_state(64),
            factories.make_keccak_hash(): make_unlock_partial_proof_state(128),
        },
    )
    unlock_gain = get_batch_unlock_gain(channel_state)
    assert unlock_gain.from_partner_locks == 192
    assert unlock_gain.from_our_locks == 7


def test_handle_block_closed_channel():
    channel_state = factories.create(
        factories.NettingChannelStateProperties(
            close_transaction=TransactionExecutionStatus(
                finished_block_number=50, result=TransactionExecutionStatus.SUCCESS
            ),
            settle_timeout=50,
        )
    )

    block = Block(block_number=90, gas_limit=100000, block_hash=factories.make_block_hash())
    before_settle = handle_block(channel_state, block, block.block_number)
    assert get_status(before_settle.new_state) == CHANNEL_STATE_CLOSED
    assert not before_settle.events

    block = Block(block_number=102, gas_limit=100000, block_hash=factories.make_block_hash())
    after_settle = handle_block(before_settle.new_state, block, block.block_number)
    assert get_status(after_settle.new_state) == CHANNEL_STATE_SETTLING
    assert after_settle.events
