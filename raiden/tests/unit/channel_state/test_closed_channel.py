# pylint: disable=too-many-locals,too-many-statements,too-many-lines
import random
from hashlib import sha256

from eth_utils import keccak

from raiden.constants import LOCKSROOT_OF_NO_LOCKS
from raiden.tests.unit.channel_state.utils import create_channel_from_models, create_model
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import (
    make_32bytes,
    make_block_hash,
    make_canonical_identifier,
    make_transaction_hash,
)
from raiden.tests.utils.transfer import make_receive_transfer_mediated
from raiden.transfer import channel
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelUpdateTransfer,
)
from raiden.transfer.state import ChannelState, HashTimeLockState, TransactionExecutionStatus
from raiden.transfer.state_change import (
    ActionChannelClose,
    ContractReceiveChannelClosed,
    ContractReceiveChannelSettled,
    ContractReceiveUpdateTransfer,
)


def test_action_close_must_change_the_channel_state():
    """A closed channel must not be used for transactions, even if the
    transaction was not confirmed on-chain.
    """
    our_model1, _ = create_model(70)
    partner_model1, partner_key1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_key1)

    block_number = 10
    state_change = ActionChannelClose(canonical_identifier=channel_state.canonical_identifier)
    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=make_block_hash(),
        pseudo_random_generator=random.Random(),
    )
    assert channel.get_status(iteration.new_state) == ChannelState.STATE_CLOSING


def test_update_must_be_called_if_close_lost_race():
    """If both participants call close, the node that lost the transaction
    race must call updateTransfer.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = keccak(b"test_update_must_be_called_if_close_lost_race")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state, privkey2, nonce, transferred_amount, lock
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)
    assert is_valid, msg

    block_number = 10
    state_change = ActionChannelClose(canonical_identifier=channel_state.canonical_identifier)
    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=make_block_hash(),
        pseudo_random_generator=random.Random(),
    )

    state_change = ContractReceiveChannelClosed(
        transaction_hash=make_transaction_hash(),
        transaction_from=partner_model1.participant_address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=77,
        block_hash=make_block_hash(),
    )
    iteration = channel._handle_channel_closed(state_change, channel_state)
    assert search_for_item(iteration.events, ContractSendChannelUpdateTransfer, {}) is not None


def test_update_transfer():
    """This tests that receiving an update transfer event for a
    closed channel sets the update_transaction member
    """
    our_model1, _ = create_model(70)
    partner_model1, partner_key1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_key1)

    pseudo_random_generator = random.Random()

    block_number = 10
    state_change = ActionChannelClose(canonical_identifier=channel_state.canonical_identifier)
    iteration = channel.state_transition(
        channel_state=channel_state,
        state_change=state_change,
        block_number=block_number,
        block_hash=make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    # update_transaction in channel state should not be set
    channel_state = iteration.new_state
    assert channel_state.update_transaction is None

    closed_block_number = 15
    closed_block_hash = make_block_hash()
    channel_close_state_change = ContractReceiveChannelClosed(
        transaction_hash=make_transaction_hash(),
        transaction_from=partner_model1.participant_address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )
    iteration2 = channel._handle_channel_closed(channel_close_state_change, channel_state)

    # update_transaction in channel state should not be set because there was no transfer
    channel_state = iteration2.new_state
    assert channel_state.update_transaction is None

    update_transfer_state_change = ContractReceiveUpdateTransfer(
        transaction_hash=partner_model1.participant_address,
        canonical_identifier=channel_state.canonical_identifier,
        nonce=23,
        block_number=closed_block_number + 1,
        block_hash=make_block_hash(),
    )

    update_block_number = 20
    iteration3 = channel._handle_channel_updated_transfer(
        update_transfer_state_change, channel_state, update_block_number
    )

    # now update_transaction in channel state should be set
    channel_state = iteration3.new_state
    assert channel_state.update_transaction == TransactionExecutionStatus(
        started_block_number=None,
        finished_block_number=update_block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )


def test_channelstate_unlock_without_locks():
    """Event close must be properly handled if there are no locks to unlock"""
    our_model1, _ = create_model(70)
    partner_model1, partner_key1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_key1)

    state_change = ContractReceiveChannelClosed(
        transaction_hash=make_transaction_hash(),
        transaction_from=our_model1.participant_address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=77,
        block_hash=make_block_hash(),
    )
    iteration = channel._handle_channel_closed(state_change, channel_state)
    assert not iteration.events


def test_channelstate_unlock_unlocked_onchain():
    """The node must call unlock after the channel is settled"""
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, privkey2)

    lock_amount = 10
    lock_expiration = 100
    lock_secret = keccak(b"test_channelstate_lockedtransfer_overspent")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state, privkey2, nonce, transferred_amount, lock
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(channel_state, receive_lockedtransfer)
    assert is_valid, msg

    channel.register_onchain_secret(
        channel_state=channel_state,
        secret=lock_secret,
        secrethash=lock_secrethash,
        secret_reveal_block_number=lock_expiration - 1,
    )

    closed_block_number = lock_expiration - channel_state.reveal_timeout - 1
    closed_block_hash = make_block_hash()
    close_state_change = ContractReceiveChannelClosed(
        transaction_hash=make_transaction_hash(),
        transaction_from=partner_model1.participant_address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )
    iteration = channel._handle_channel_closed(close_state_change, channel_state)
    assert search_for_item(iteration.events, ContractSendChannelBatchUnlock, {}) is None

    settle_block_number = lock_expiration + channel_state.reveal_timeout + 1
    settle_state_change = ContractReceiveChannelSettled(
        canonical_identifier=make_canonical_identifier(
            token_network_address=channel_state.token_network_address,
            channel_identifier=channel_state.identifier,
        ),
        transaction_hash=make_transaction_hash(),
        block_number=settle_block_number,
        block_hash=make_block_hash(),
        partner_onchain_locksroot=make_32bytes(),  # non empty
        partner_transferred_amount=0,
        our_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        our_transferred_amount=0,
    )

    iteration = channel._handle_channel_settled(settle_state_change, channel_state)
    assert search_for_item(iteration.events, ContractSendChannelBatchUnlock, {}) is not None
