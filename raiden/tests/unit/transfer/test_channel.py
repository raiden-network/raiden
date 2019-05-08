from copy import deepcopy

from raiden.constants import MAXIMUM_PENDING_TRANSFERS
from raiden.tests.unit.test_channelstate import (
    create_channel_from_models,
    create_model,
    make_receive_transfer_mediated,
)
from raiden.tests.utils.factories import make_block_hash, make_transaction_hash
from raiden.transfer import channel
from raiden.transfer.merkle_tree import merkleroot
from raiden.transfer.state import HashTimeLockState
from raiden.transfer.state_change import (
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelSettled,
)
from raiden.utils import sha3


def _channel_and_transfer(merkletree_width):
    our_model, _ = create_model(700)
    partner_model, privkey = create_model(700, merkletree_width)
    reverse_channel_state = create_channel_from_models(partner_model, our_model, privkey)

    lock_secret = sha3(b"some secret")
    lock = HashTimeLockState(30, 10, sha3(lock_secret))

    mediated_transfer = make_receive_transfer_mediated(
        reverse_channel_state,
        privkey,
        nonce=1,
        transferred_amount=0,
        lock=lock,
        merkletree_leaves=partner_model.merkletree_leaves + [lock.lockhash],
        locked_amount=lock.amount,
    )

    channel_state = deepcopy(reverse_channel_state)
    channel_state.our_state = reverse_channel_state.partner_state
    channel_state.partner_state = reverse_channel_state.our_state

    return channel_state, mediated_transfer


def test_handle_receive_lockedtransfer_enforces_transfer_limit():

    state, transfer = _channel_and_transfer(merkletree_width=MAXIMUM_PENDING_TRANSFERS - 1)
    is_valid, _, _ = channel.handle_receive_lockedtransfer(state, transfer)
    assert is_valid

    state, transfer = _channel_and_transfer(merkletree_width=MAXIMUM_PENDING_TRANSFERS)
    is_valid, _, _ = channel.handle_receive_lockedtransfer(state, transfer)
    assert not is_valid


def test_channel_cleared_after_all_unlocks():
    our_model, _ = create_model(balance=700, merkletree_width=1)
    partner_model, partner_key1 = create_model(balance=700, merkletree_width=1)
    channel_state = create_channel_from_models(partner_model, our_model, partner_key1)
    block_number = 1
    block_hash = make_block_hash()

    def make_unlock(unlock_end, partner_end):
        batch_unlock = ContractReceiveChannelBatchUnlock(
            transaction_hash=make_transaction_hash(),
            canonical_identifier=channel_state.canonical_identifier,
            participant=unlock_end.address,
            partner=partner_end.address,
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
        our_onchain_locksroot=merkleroot(channel_state.our_state.merkletree),
        partner_onchain_locksroot=merkleroot(channel_state.partner_state.merkletree),
        block_number=1,
        block_hash=make_block_hash(),
    )
    iteration = channel.state_transition(channel_state, settle_channel, block_number, block_hash)

    batch_unlock = make_unlock(channel_state.our_state, channel_state.partner_state)
    iteration = channel.state_transition(
        iteration.new_state, batch_unlock, block_number, block_hash
    )
    msg = "partner locksroot is not unlocked, channel should not have been cleaned"
    assert iteration.new_state is not None, msg

    # processing the same unlock twice must not count
    iteration = channel.state_transition(
        iteration.new_state, batch_unlock, block_number, block_hash
    )
    msg = "partner locksroot is not unlocked, channel should not have been cleaned"
    assert iteration.new_state is not None, msg

    iteration = channel.state_transition(
        iteration.new_state,
        make_unlock(channel_state.partner_state, channel_state.our_state),
        block_number,
        block_hash,
    )
    msg = "all unlocks have been done, channel must be cleared"
    assert iteration.new_state is None, msg
