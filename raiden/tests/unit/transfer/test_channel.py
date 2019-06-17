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
    handle_receive_lockedtransfer,
    is_balance_proof_usable_onchain,
)
from raiden.transfer.state import HashTimeLockState, PendingLocksState
from raiden.transfer.state_change import (
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
        pending_locks=PendingLocksState(
            {**partner_model.pending_locks, lock.lockhash: lock.encoded}
        ),
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
