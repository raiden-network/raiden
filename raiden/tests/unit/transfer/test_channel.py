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
from raiden.tests.utils.factories import (
    NettingChannelEndStateProperties,
    make_block_hash,
    make_transaction_hash,
)
from raiden.transfer import channel
from raiden.transfer.channel import (
    compute_locksroot,
    get_batch_unlock_gain,
    get_secret,
    get_status,
    handle_block,
    handle_receive_lockedtransfer,
    is_balance_proof_usable_onchain,
    is_valid_balanceproof_signature,
    set_settled,
    update_fee_schedule_after_balance_change,
)
from raiden.transfer.events import EventInvalidActionSetRevealTimeout, SendPFSFeeUpdate
from raiden.transfer.state import (
    ChannelState,
    HashTimeLockState,
    PendingLocksState,
    TransactionExecutionStatus,
    UnlockPartialProofState,
)
from raiden.transfer.state_change import (
    ActionChannelSetRevealTimeout,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelSettled,
)
from raiden.utils import sha3
from raiden.utils.mediation_fees import prepare_mediation_fee_config
from raiden.utils.typing import BlockExpiration, TokenAmount


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
    is_valid_balance_proof = is_balance_proof_usable_onchain(
        received_balance_proof=balance_proof_wrong_channel,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
    )
    assert is_valid_balance_proof.fail

    error_message = is_valid_balance_proof.as_error_message
    assert error_message.startswith("channel_identifier does not match. "), error_message

    wrong_token_network_canonical_identifier = replace(
        channel_state.canonical_identifier, token_network_address=factories.make_address()
    )

    balance_proof_wrong_token_network = factories.create(
        factories.BalanceProofSignedStateProperties(
            canonical_identifier=wrong_token_network_canonical_identifier
        )
    )
    is_valid_balance_proof = is_balance_proof_usable_onchain(
        received_balance_proof=balance_proof_wrong_token_network,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
    )
    assert is_valid_balance_proof.fail
    error_message = is_valid_balance_proof.as_error_message
    assert error_message.startswith("token_network_address does not match. "), error_message

    balance_proof_overflow = factories.create(
        factories.BalanceProofSignedStateProperties(
            transferred_amount=factories.UINT256_MAX,
            locked_amount=1,
            canonical_identifier=channel_state.canonical_identifier,
        )
    )
    is_valid_balance_proof = is_balance_proof_usable_onchain(
        received_balance_proof=balance_proof_overflow,
        channel_state=channel_state,
        sender_state=channel_state.partner_state,
    )
    assert is_valid_balance_proof.fail

    msg = is_valid_balance_proof.as_error_message
    assert msg.startswith("Balance proof total transferred amount would overflow "), msg
    assert str(factories.UINT256_MAX) in msg, msg
    assert str(factories.UINT256_MAX + 1) in msg, msg


def test_is_valid_balanceproof_signature():
    balance_proof = factories.create(factories.BalanceProofSignedStateProperties())
    valid = is_valid_balanceproof_signature(balance_proof, factories.make_address())
    assert not valid, "Address does not match."

    balance_proof = factories.create(
        factories.BalanceProofSignedStateProperties(signature=b"\0" * 65)
    )
    valid = is_valid_balanceproof_signature(balance_proof, factories.make_address())
    assert not valid, f"Invalid signature check: {valid.as_error_message}"


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
    assert get_status(close_failed) == ChannelState.STATE_UNUSABLE

    settle_failed = factories.create(
        factories.NettingChannelStateProperties(settle_transaction=failed_status)
    )
    assert get_status(settle_failed) == ChannelState.STATE_UNUSABLE


def test_set_settled():
    channel = factories.create(
        factories.NettingChannelStateProperties(
            settle_transaction=TransactionExecutionStatus(finished_block_number=None, result=None)
        )
    )

    assert get_status(channel) == ChannelState.STATE_SETTLING
    set_settled(channel, block_number=100)
    assert get_status(channel) == ChannelState.STATE_SETTLED


def make_hash_time_lock_state(amount) -> HashTimeLockState:
    return HashTimeLockState(
        amount=amount, expiration=BlockExpiration(5), secrethash=factories.UNIT_SECRETHASH
    )


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
    pseudo_random_generator = random.Random()
    block = Block(block_number=90, gas_limit=100000, block_hash=factories.make_block_hash())
    before_settle = handle_block(
        channel_state=channel_state,
        state_change=block,
        block_number=block.block_number,
        pseudo_random_generator=pseudo_random_generator,
    )
    assert get_status(before_settle.new_state) == ChannelState.STATE_CLOSED
    assert not before_settle.events

    block = Block(block_number=102, gas_limit=100000, block_hash=factories.make_block_hash())
    after_settle = handle_block(
        channel_state=before_settle.new_state,
        state_change=block,
        block_number=block.block_number,
        pseudo_random_generator=pseudo_random_generator,
    )
    assert get_status(after_settle.new_state) == ChannelState.STATE_SETTLING
    assert after_settle.events


def test_get_capacity():
    our_state = factories.create(
        factories.NettingChannelEndStateProperties(balance=TokenAmount(100))
    )
    channel_state = factories.create(
        factories.NettingChannelStateProperties(
            our_state=our_state,
            partner_state=factories.NettingChannelEndStateProperties(balance=TokenAmount(50)),
        )
    )
    assert channel.get_capacity(channel_state) == 150

    channel_state.our_state = replace(our_state, onchain_total_withdraw=50)
    assert channel.get_capacity(channel_state) == 100


def test_update_fee_schedule_after_balance_change():
    channel_state = factories.create(
        factories.NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=100),
            partner_state=NettingChannelEndStateProperties(balance=0),
        )
    )

    fee_config = prepare_mediation_fee_config(
        cli_token_to_flat_fee=(),
        cli_token_to_proportional_fee=(),
        cli_token_to_proportional_imbalance_fee=((channel_state.token_address, 50_000),),  # 5%
        cli_cap_mediation_fees=True,
    )
    events = update_fee_schedule_after_balance_change(channel_state, fee_config)
    assert isinstance(events[0], SendPFSFeeUpdate)
    assert channel_state.fee_schedule.imbalance_penalty[0] == (0, 5)


def test_update_channel_reveal_timeout():
    pseudo_random_generator = random.Random()
    channel_state = factories.create(
        factories.NettingChannelStateProperties(settle_timeout=500, reveal_timeout=50)
    )

    invalid_reveal_timeout = 260
    valid_reveal_timeout = 250

    set_reveal_timeout = ActionChannelSetRevealTimeout(
        canonical_identifier=channel_state.canonical_identifier,
        reveal_timeout=invalid_reveal_timeout,
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=set_reveal_timeout,
        block_number=1,
        block_hash=make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    assert iteration.new_state == channel_state
    assert isinstance(iteration.events[0], EventInvalidActionSetRevealTimeout)

    set_reveal_timeout = ActionChannelSetRevealTimeout(
        canonical_identifier=channel_state.canonical_identifier, reveal_timeout=250
    )

    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=set_reveal_timeout,
        block_number=1,
        block_hash=make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    assert iteration.new_state.reveal_timeout == valid_reveal_timeout
