from copy import deepcopy

from raiden.constants import EMPTY_MERKLE_ROOT, MAXIMUM_PENDING_TRANSFERS
from raiden.tests.unit.test_channelstate import (
    create_channel_from_models,
    create_model,
    make_receive_transfer_mediated,
)
from raiden.tests.utils import factories
from raiden.tests.utils.factories import make_block_hash, make_transaction_hash
from raiden.transfer import channel
from raiden.transfer.channel import handle_receive_lockedtransfer, is_balance_proof_usable_onchain
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

    lock_secret = sha3(b"some secret seed")
    lock = HashTimeLockState(30, 10, sha3(lock_secret))

    mediated_transfer = make_receive_transfer_mediated(
        reverse_channel_state,
        privkey,
        nonce=partner_model.next_nonce,
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
    is_valid, _, msg = channel.handle_receive_lockedtransfer(state, transfer)
    assert is_valid, msg

    state, transfer = _channel_and_transfer(merkletree_width=MAXIMUM_PENDING_TRANSFERS)
    is_valid, _, _ = handle_receive_lockedtransfer(state, transfer)
    assert not is_valid


def test_channel_cleared_after_two_unlocks():
    our_model, _ = create_model(balance=700, merkletree_width=1)
    partner_model, partner_key1 = create_model(balance=700, merkletree_width=1)
    channel_state = create_channel_from_models(our_model, partner_model, partner_key1)
    block_number = 1
    block_hash = make_block_hash()

    def make_unlock(unlock_end, partner_end):
        batch_unlock = ContractReceiveChannelBatchUnlock(
            transaction_hash=make_transaction_hash(),
            canonical_identifier=channel_state.canonical_identifier,
            participant=partner_end.address,
            partner=unlock_end.address,
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

    msg = "both participants have pending locks, merkleroot must not be empty"
    assert iteration.new_state.our_state.onchain_locksroot is not EMPTY_MERKLE_ROOT, msg
    assert iteration.new_state.partner_state.onchain_locksroot is not EMPTY_MERKLE_ROOT, msg

    batch_unlock = make_unlock(channel_state.our_state, channel_state.partner_state)
    iteration = channel.state_transition(
        iteration.new_state, batch_unlock, block_number, block_hash
    )
    msg = "all of our locks has been unlocked, onchain state must be updated"
    assert iteration.new_state.our_state.onchain_locksroot is EMPTY_MERKLE_ROOT, msg
    msg = "partner has pending locks, the merkleroot must not be cleared"
    assert iteration.new_state.partner_state.onchain_locksroot is not EMPTY_MERKLE_ROOT, msg
    msg = "partner locksroot is not unlocked, channel should not have been cleaned"
    assert iteration.new_state is not None, msg

    # processing the same unlock twice must not count
    iteration = channel.state_transition(
        iteration.new_state, batch_unlock, block_number, block_hash
    )
    msg = "partner has pending locks, the merkleroot must not be cleared"
    assert iteration.new_state.partner_state.onchain_locksroot is not EMPTY_MERKLE_ROOT, msg
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


def test_channel_cleared_after_our_unlock():
    our_model, _ = create_model(balance=700, merkletree_width=1)
    partner_model, partner_key1 = create_model(balance=700, merkletree_width=0)
    channel_state = create_channel_from_models(our_model, partner_model, partner_key1)
    block_number = 1
    block_hash = make_block_hash()

    def make_unlock(unlock_end, partner_end):
        batch_unlock = ContractReceiveChannelBatchUnlock(
            transaction_hash=make_transaction_hash(),
            canonical_identifier=channel_state.canonical_identifier,
            participant=partner_end.address,
            partner=unlock_end.address,
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

    assert settle_channel.our_onchain_locksroot is not EMPTY_MERKLE_ROOT
    assert settle_channel.partner_onchain_locksroot is EMPTY_MERKLE_ROOT

    iteration = channel.state_transition(channel_state, settle_channel, block_number, block_hash)

    batch_unlock = make_unlock(channel_state.our_state, channel_state.partner_state)
    iteration = channel.state_transition(
        iteration.new_state, batch_unlock, block_number, block_hash
    )
    msg = "partner did not have any locks in the merkletree, channel should have been cleaned"
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

    wrong_token_network_canonical_identifier = deepcopy(channel_state.canonical_identifier)
    wrong_token_network_canonical_identifier.token_network_address = factories.make_address()

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
    assert msg.startswith("token_network_identifier does not match. "), msg

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
