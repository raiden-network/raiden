# -*- coding: utf-8 -*-
# pylint: disable=too-many-locals,too-many-statements,too-many-lines

from collections import namedtuple
from copy import deepcopy
from itertools import cycle

import pytest
from ethereum import slogging

from raiden.messages import (
    DirectTransfer,
    MediatedTransfer,
    Secret,
)
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.transfer import channel
from raiden.transfer.mediated_transfer.state import LockedTransferSignedState
from raiden.transfer.merkle_tree import (
    LEAVES,
    MERKLEROOT,
    compute_layers,
    merkleroot,
)
from raiden.transfer.events import (
    ContractSendChannelWithdraw,
    EventTransferReceivedInvalidDirectTransfer,
    EventTransferReceivedSuccess,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelNewBalance,
    ReceiveTransferDirect2,
    ReceiveUnlock,
)
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    EMPTY_MERKLE_ROOT,
    balanceproof_from_envelope,
    HashTimeLockState,
    NettingChannelEndState,
    NettingChannelState,
    TransactionExecutionStatus,
)
from raiden.utils import (
    sha3,
    privatekey_to_address,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


PartnerStateModel = namedtuple(
    'PartnerStateModel',
    (
        'participant_address',
        'amount_locked',
        'balance',
        'distributable',
        'next_nonce',
        'merkletree_leaves',
        'contract_balance',
    ),
)


def assert_partner_state(end_state, partner_state, model):
    """Checks that the stored data for both ends correspond to the model."""
    assert end_state.address == model.participant_address
    assert channel.get_amount_locked(end_state) == model.amount_locked
    assert channel.get_balance(end_state, partner_state) == model.balance
    assert channel.get_distributable(end_state, partner_state) == model.distributable
    assert channel.get_next_nonce(end_state) == model.next_nonce
    assert set(end_state.merkletree.layers[LEAVES]) == set(model.merkletree_leaves)
    assert end_state.contract_balance == model.contract_balance


def create_model(balance):
    privkey, address = factories.make_privkey_address()

    our_model = PartnerStateModel(
        participant_address=address,
        amount_locked=0,
        balance=balance,
        distributable=balance,
        next_nonce=1,
        merkletree_leaves=[],
        contract_balance=balance,
    )

    return our_model, privkey


def create_channel_from_models(our_model, partner_model):
    """Utility to instantiate state objects used throughout the tests."""
    our_state = NettingChannelEndState(
        our_model.participant_address,
        our_model.balance,
    )
    partner_state = NettingChannelEndState(
        partner_model.participant_address,
        partner_model.balance,
    )

    identifier = factories.make_address()
    token_address = factories.make_address()
    reveal_timeout = 10
    settle_timeout = 100
    opened_transaction = TransactionExecutionStatus(
        None,
        1,
        TransactionExecutionStatus.SUCCESS,
    )
    closed_transaction = None
    settled_transaction = None
    channel_state = CHANNEL_STATE_OPENED

    channel_state = NettingChannelState(
        identifier,
        token_address,
        reveal_timeout,
        settle_timeout,
        our_state,
        partner_state,
        opened_transaction,
        closed_transaction,
        settled_transaction,
    )

    assert_partner_state(
        channel_state.our_state,
        channel_state.partner_state,
        our_model,
    )

    assert_partner_state(
        channel_state.partner_state,
        channel_state.our_state,
        partner_model,
    )

    return channel_state


def make_receive_transfer_direct(
        channel_state,
        privkey,
        nonce,
        transferred_amount,
        locksroot=EMPTY_MERKLE_ROOT):

    address = privatekey_to_address(privkey.secret)
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError('Private key does not match any of the participants.')

    identifier = nonce
    mediated_transfer_msg = DirectTransfer(
        identifier,
        nonce,
        channel_state.token_address,
        channel_state.identifier,
        transferred_amount,
        channel_state.partner_state.address,
        locksroot,
    )
    mediated_transfer_msg.sign(privkey, address)

    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)

    receive_directtransfer = ReceiveTransferDirect2(
        identifier,
        channel_state.token_address,
        balance_proof,
    )

    return receive_directtransfer


def make_receive_transfer_mediated(
        channel_state,
        privkey,
        nonce,
        transferred_amount,
        lock,
        merkletree_leaves=None):

    if not isinstance(lock, HashTimeLockState):
        raise ValueError('lock must be of type HashTimeLockState')

    address = privatekey_to_address(privkey.secret)
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError('Private key does not match any of the participants.')

    if merkletree_leaves is None:
        layers = [[lock.lockhash]]
    else:
        assert lock.lockhash in merkletree_leaves
        layers = compute_layers(merkletree_leaves)

    locksroot = layers[MERKLEROOT][0]

    identifier = nonce
    transfer_target = factories.make_address()
    transfer_initiator = factories.make_address()
    mediated_transfer_msg = MediatedTransfer(
        identifier,
        nonce,
        channel_state.token_address,
        channel_state.identifier,
        transferred_amount,
        channel_state.partner_state.address,
        locksroot,
        lock,
        transfer_target,
        transfer_initiator,
    )
    mediated_transfer_msg.sign(privkey, address)

    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)

    receive_mediatedtransfer = LockedTransferSignedState(
        identifier,
        channel_state.token_address,
        balance_proof,
        lock,
        transfer_initiator,
        transfer_target,
    )

    return receive_mediatedtransfer


def test_new_end_state():
    """Test the defaults for an end state object."""
    balance1 = 101
    node_address = factories.make_address()
    end_state = NettingChannelEndState(node_address, balance1)

    lock_secret = sha3(b'test_end_state')
    lock_hashlock = sha3(lock_secret)

    assert channel.is_known(end_state, lock_hashlock) is False
    assert channel.is_locked(end_state, lock_hashlock) is False
    assert channel.get_next_nonce(end_state) == 1
    assert channel.get_amount_locked(end_state) == 0
    assert not channel.get_known_unlocks(end_state)
    assert merkleroot(end_state.merkletree) == EMPTY_MERKLE_ROOT

    assert not end_state.hashlocks_to_pendinglocks
    assert not end_state.hashlocks_to_unclaimedlocks


def test_endstate_update_contract_balance():
    """The balance must be monotonic."""
    balance1 = 101
    node_address = factories.make_address()

    end_state = NettingChannelEndState(node_address, balance1)
    assert end_state.contract_balance == balance1

    channel.update_contract_balance(end_state, balance1 - 10)
    assert end_state.contract_balance == balance1

    channel.update_contract_balance(end_state, balance1 + 10)
    assert end_state.contract_balance == balance1 + 10


def test_channelstate_update_contract_balance():
    """A blockchain event for a new balance must increase the respective
    participants balance.
    """
    block_number = 10

    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    deposit_amount = 10
    balance1_new = our_model1.balance + deposit_amount
    state_change = ContractReceiveChannelNewBalance(
        channel_state.identifier,
        our_model1.participant_address,
        balance1_new,
    )

    iteration = channel.state_transition(
        deepcopy(channel_state),
        state_change,
        block_number,
    )
    new_state = iteration.new_state

    our_model2 = our_model1._replace(
        balance=balance1_new,
        distributable=balance1_new,
        contract_balance=balance1_new,
    )
    partner_model2 = partner_model1

    assert_partner_state(new_state.our_state, new_state.partner_state, our_model2)
    assert_partner_state(new_state.partner_state, new_state.our_state, partner_model2)


def test_channelstate_decreasing_contract_balance():
    """A blockchain event for a new balance that decrease the balance must be
    ignored.
    """
    block_number = 10

    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    amount = 10
    balance1_new = our_model1.balance - amount
    state_change = ContractReceiveChannelNewBalance(
        channel_state.identifier,
        our_model1.participant_address,
        balance1_new,
    )

    iteration = channel.state_transition(
        deepcopy(channel_state),
        state_change,
        block_number,
    )
    new_state = iteration.new_state

    assert_partner_state(new_state.our_state, new_state.partner_state, our_model1)
    assert_partner_state(new_state.partner_state, new_state.our_state, partner_model1)


def test_channelstate_repeated_contract_balance():
    """Handling the same blockchain event multiple times must change the
    balance only once.
    """
    block_number = 10

    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    deposit_amount = 10
    balance1_new = our_model1.balance + deposit_amount
    state_change = ContractReceiveChannelNewBalance(
        channel_state.identifier,
        our_model1.participant_address,
        balance1_new,
    )

    our_model2 = our_model1._replace(
        balance=balance1_new,
        distributable=balance1_new,
        contract_balance=balance1_new,
    )
    partner_model2 = partner_model1

    for _ in range(10):
        iteration = channel.state_transition(
            deepcopy(channel_state),
            state_change,
            block_number,
        )
        new_state = iteration.new_state

        assert_partner_state(new_state.our_state, new_state.partner_state, our_model2)
        assert_partner_state(new_state.partner_state, new_state.our_state, partner_model2)


def test_channelstate_send_mediatedtransfer():
    """Sending a mediated transfer must update the participant state.

    This tests only the state of the sending node, without synchronisation.
    """
    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_end_state')
    lock_hashlock = sha3(lock_secret)

    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )

    identifier = 1
    transfer_target = factories.make_address()
    transfer_initiator = factories.make_address()

    channel.send_mediatedtransfer(
        channel_state,
        transfer_initiator,
        transfer_target,
        lock_amount,
        identifier,
        lock_expiration,
        lock_hashlock,
    )

    our_model2 = our_model1._replace(
        distributable=our_model1.distributable - lock_amount,
        amount_locked=lock_amount,
        next_nonce=2,
        merkletree_leaves=[lock.lockhash],
    )
    partner_model2 = partner_model1

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)


def test_channelstate_send_direct_transfer():
    """Sending a direct transfer must update the participant state.

    This tests only the state of the sending node, without synchronisation.
    """
    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    amount = 30
    identifier = 1
    channel.send_directtransfer(
        channel_state,
        amount,
        identifier,
    )

    our_model2 = our_model1._replace(
        distributable=our_model1.distributable - amount,
        balance=our_model1.balance - amount,
        next_nonce=2,
    )
    partner_model2 = partner_model1._replace(
        distributable=partner_model1.distributable + amount,
        balance=partner_model1.balance + amount,
    )

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)


def test_channelstate_receive_mediatedtransfer():
    """Tests receiving a mediated transfer.

    The transfer is done in three steps:
        - a mediated transfer including a lock in its balance proof is sent
        - the secret is revealed
        - the unlocked balance proof is sent updating the transferred_amount
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    # Step 1: Simulate receiving a transfer
    # - The receiver end state doesnt change
    # - The lock must be registered with the sender end
    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_end_state')
    lock_hashlock = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )

    nonce = 1
    transferred_amount = 0
    receive_mediatedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, msg = channel.handle_receive_mediatedtransfer(
        channel_state,
        receive_mediatedtransfer,
    )
    assert is_valid, msg

    our_model2 = our_model1
    partner_model2 = partner_model1._replace(
        distributable=partner_model1.distributable - lock_amount,
        amount_locked=lock_amount,
        next_nonce=2,
        merkletree_leaves=[lock.lockhash],
    )
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)

    # Step 2: Simulate learning the secret
    # - Registers the secret, this must not change the balance/locked amount
    channel.register_secret(channel_state, lock_secret, lock_hashlock)

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)

    # Step 3: Simulate unlocking the lock
    # - Update the balances
    transferred_amount = 0
    secret_message = Secret(
        identifier=1,
        nonce=2,
        channel=channel_state.identifier,
        transferred_amount=transferred_amount + lock_amount,
        locksroot=EMPTY_MERKLE_ROOT,
        secret=lock_secret,
    )
    secret_message.sign(privkey2, channel_state.partner_state.address)

    balance_proof = balanceproof_from_envelope(secret_message)
    unlock_state_change = ReceiveUnlock(
        lock_secret,
        balance_proof,
    )

    is_valid, msg = channel.handle_unlock(channel_state, unlock_state_change)
    assert is_valid, msg

    our_model3 = our_model2._replace(
        balance=our_model2.balance + lock_amount,
        distributable=our_model2.balance + lock_amount,
    )
    partner_model3 = partner_model2._replace(
        balance=partner_model2.balance - lock_amount,
        amount_locked=0,
        next_nonce=3,
        merkletree_leaves=[],
    )

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model3)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model3)


def test_channelstate_directtransfer_overspent():
    """Receiving a direct transfer with an amount large than distributable must
    be ignored.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)

    nonce = 1
    transferred_amount = distributable + 1
    receive_mediatedtransfer = make_receive_transfer_direct(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
    )

    is_valid, _ = channel.is_valid_directtransfer(
        receive_mediatedtransfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )
    assert not is_valid, 'message is invalid because it is spending more than the distributable'

    iteration = channel.handle_receive_directtransfer(
        channel_state,
        receive_mediatedtransfer,
    )

    assert must_contain_entry(iteration.events, EventTransferReceivedInvalidDirectTransfer, {})
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_mediatedtransfer_overspent():
    """Receiving a lock with an amount large than distributable must be
    ignored.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)

    lock_amount = distributable + 1
    lock_expiration = 10
    lock_hashlock = sha3(b'test_channelstate_mediatedtransfer_overspent')
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )

    nonce = 1
    transferred_amount = 0
    receive_mediatedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _ = channel.handle_receive_mediatedtransfer(
        channel_state,
        receive_mediatedtransfer,
    )
    assert not is_valid, 'message is invalid because it is spending more than the distributable'

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_mediatedtransfer_overspend_with_multiple_pending_transfers():
    """Receiving a concurrent lock with an amount large than distributable
    must be ignored.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    # Step 1: Create a lock with an amount of 1
    # - this wont be unlocked
    lock1_amount = 1
    lock1_expiration = 1 + channel_state.settle_timeout
    lock1_hashlock = sha3(b'test_receive_cannot_overspend_with_multiple_pending_transfers1')
    lock1 = HashTimeLockState(
        lock1_amount,
        lock1_expiration,
        lock1_hashlock,
    )

    nonce1 = 1
    transferred_amount = 0
    receive_mediatedtransfer1 = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce1,
        transferred_amount,
        lock1,
    )

    is_valid, msg = channel.handle_receive_mediatedtransfer(
        channel_state,
        receive_mediatedtransfer1,
    )
    assert is_valid, msg

    our_model2 = our_model1
    partner_model2 = partner_model1._replace(
        distributable=partner_model1.distributable - lock1.amount,
        amount_locked=lock1.amount,
        next_nonce=2,
        merkletree_leaves=[lock1.lockhash],
    )

    # The valid transfer is handled normally
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)

    # Step 2: Create a lock with the current *distributable + 1*
    # - This must be ignored
    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)
    lock2_amount = distributable + 1
    lock2_expiration = channel_state.settle_timeout
    lock2_hashlock = sha3(b'test_receive_cannot_overspend_with_multiple_pending_transfers2')
    lock2 = HashTimeLockState(
        lock2_amount,
        lock2_expiration,
        lock2_hashlock,
    )
    leaves = [lock1.lockhash, lock2.lockhash]

    nonce2 = 2
    receive_mediatedtransfer2 = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce2,
        transferred_amount,
        lock2,
        merkletree_leaves=leaves,
    )

    is_valid, msg = channel.handle_receive_mediatedtransfer(
        channel_state,
        receive_mediatedtransfer2,
    )
    assert not is_valid, 'message is invalid because its expending more than the distributable'

    # The overspending transfer must be ignored
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)


def test_invalid_timeouts():
    token_address = factories.make_address()
    reveal_timeout = 5
    settle_timeout = 10
    identifier = factories.make_address()

    address1 = factories.make_address()
    address2 = factories.make_address()
    balance1 = 10
    balance2 = 10

    opened_transaction = TransactionExecutionStatus(
        None,
        1,
        TransactionExecutionStatus.SUCCESS,
    )
    closed_transaction = None
    settled_transaction = None

    our_state = NettingChannelEndState(address1, balance1)
    partner_state = NettingChannelEndState(address2, balance2)

    # do not allow a reveal timeout larger than the settle timeout
    with pytest.raises(ValueError):
        large_reveal_timeout = 50
        small_settle_timeout = 49

        NettingChannelState(
            identifier,
            token_address,
            large_reveal_timeout,
            small_settle_timeout,
            our_state,
            partner_state,
            opened_transaction,
            closed_transaction,
            settled_transaction,
        )

    # TypeError: 'a', [], {}
    for invalid_value in (-1, 0, 1.1, 1.0):
        with pytest.raises(ValueError):
            NettingChannelState(
                identifier,
                token_address,
                invalid_value,
                settle_timeout,
                our_state,
                partner_state,
                opened_transaction,
                closed_transaction,
                settled_transaction,
            )

        with pytest.raises(ValueError):
            NettingChannelState(
                identifier,
                token_address,
                reveal_timeout,
                invalid_value,
                our_state,
                partner_state,
                opened_transaction,
                closed_transaction,
                settled_transaction,
            )


def test_interwoven_transfers():
    """Can keep doing transactions even if not all secrets have been released."""
    number_of_transfers = 100
    balance_for_all_transfers = 11 * number_of_transfers

    lock_amounts = cycle([1, 3, 5, 7, 11])
    lock_secrets = [
        format(i, '>032').encode()
        for i in range(number_of_transfers)
    ]

    our_model, _ = create_model(70)
    partner_model, privkey2 = create_model(balance_for_all_transfers)
    channel_state = create_channel_from_models(our_model, partner_model)

    block_number = 1000
    nonce = 0
    transferred_amount = 0
    our_model_current = our_model
    partner_model_current = partner_model

    for i, (lock_amount, lock_secret) in enumerate(zip(lock_amounts, lock_secrets)):
        nonce += 1
        block_number += 1

        lock_expiration = block_number + channel_state.settle_timeout - 1
        lock_hashlock = sha3(lock_secret)
        lock = HashTimeLockState(
            lock_amount,
            lock_expiration,
            lock_hashlock,
        )

        merkletree_leaves = list(partner_model_current.merkletree_leaves)
        merkletree_leaves.append(lock.lockhash)

        partner_model_current = partner_model_current._replace(
            distributable=partner_model_current.distributable - lock_amount,
            amount_locked=partner_model_current.amount_locked + lock_amount,
            next_nonce=partner_model_current.next_nonce + 1,
            merkletree_leaves=merkletree_leaves,
        )

        receive_mediatedtransfer = make_receive_transfer_mediated(
            channel_state,
            privkey2,
            nonce,
            transferred_amount,
            lock,
            merkletree_leaves=merkletree_leaves,
        )

        is_valid, msg = channel.handle_receive_mediatedtransfer(
            channel_state,
            receive_mediatedtransfer,
        )
        assert is_valid, msg

        assert_partner_state(
            channel_state.our_state,
            channel_state.partner_state,
            our_model_current,
        )
        assert_partner_state(
            channel_state.partner_state,
            channel_state.our_state,
            partner_model_current,
        )

        # claim a transaction at every other iteration, leaving the current one
        # in place
        if i % 2:
            # Update our model:
            # - Increase nonce because the secret is a new balance proof
            # - The lock is removed from the merkle tree, the balance proof must be updated
            #   - The locksroot must have unlocked lock removed
            #   - The transferred amount must be increased by the lock amount
            # - This changes the balance for both participants:
            #   - the sender balance and locked amount is decremented by the lock amount
            #   - the receiver balance and distributable is incremented by the lock amount
            nonce += 1
            transferred_amount += lock_amount

            merkletree_leaves = list(partner_model_current.merkletree_leaves)
            merkletree_leaves.remove(lock.lockhash)
            tree = compute_layers(merkletree_leaves)
            locksroot = tree[MERKLEROOT][0]

            partner_model_current = partner_model_current._replace(
                amount_locked=partner_model_current.amount_locked - lock_amount,
                balance=partner_model_current.balance - lock_amount,
                next_nonce=partner_model_current.next_nonce + 1,
                merkletree_leaves=merkletree_leaves,
            )

            our_model_current = our_model_current._replace(
                balance=our_model_current.balance + lock_amount,
                distributable=our_model_current.distributable + lock_amount,
            )

            secret_message = Secret(
                identifier=nonce,
                nonce=nonce,
                channel=channel_state.identifier,
                transferred_amount=transferred_amount,
                locksroot=locksroot,
                secret=lock_secret,
            )
            secret_message.sign(privkey2, channel_state.partner_state.address)

            balance_proof = balanceproof_from_envelope(secret_message)
            unlock_state_change = ReceiveUnlock(
                lock_secret,
                balance_proof,
            )

            is_valid, msg = channel.handle_unlock(channel_state, unlock_state_change)
            assert is_valid, msg

            assert_partner_state(
                channel_state.our_state,
                channel_state.partner_state,
                our_model_current,
            )
            assert_partner_state(
                channel_state.partner_state,
                channel_state.our_state,
                partner_model_current,
            )


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
    channel_state = create_channel_from_models(our_model1, partner_model1)

    block_number = 100

    lock_amount = 10
    lock_expiration = block_number - 10
    lock_hashlock = sha3(b'test_channel_must_accept_expired_locks')
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )

    nonce = 1
    transferred_amount = 0
    receive_mediatedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, msg = channel.handle_receive_mediatedtransfer(
        channel_state,
        receive_mediatedtransfer,
    )
    assert is_valid, msg

    # the locked amount must increase even though the lock is expired, this
    # will be removed by an additional synchronization message from the partner
    our_model2 = our_model1
    partner_model2 = partner_model1._replace(
        amount_locked=lock_amount,
        distributable=partner_model1.distributable - lock_amount,
        next_nonce=partner_model1.next_nonce + 1,
        merkletree_leaves=[lock.lockhash],
    )

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)


def test_receive_mediatedtransfer_before_deposit():
    """Regression test that ensures we accept incoming mediated transfers, even if we don't have
    any balance on the channel.
    """
    our_model1, _ = create_model(0)  # our deposit is 0
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_end_state')
    lock_hashlock = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )

    nonce = 1
    transferred_amount = 0
    receive_mediatedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, msg = channel.handle_receive_mediatedtransfer(
        channel_state,
        receive_mediatedtransfer,
    )

    # this node partner has enough balance, the transfer must be accepted
    assert is_valid, msg


def test_receive_directdtransfer_before_deposit():
    """Regression test that ensures that we accept incoming direct transfers,
    even if we don't have any balance on the channel.
    """
    our_model1, _ = create_model(0)  # our deposit is 0
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    nonce = 1
    transferred_amount = 30
    receive_directtransfer = make_receive_transfer_direct(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
    )

    # this node partner has enough balance, the transfer must be accepted
    iteration = channel.handle_receive_directtransfer(
        channel_state,
        receive_directtransfer,
    )
    assert must_contain_entry(iteration.events, EventTransferReceivedSuccess, {})


def test_channelstate_withdraw_without_locks():
    """Event close must be properly handled if there are no locks to unlock"""
    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    closed_block_number = 77
    state_change = ContractReceiveChannelClosed(
        channel_state.identifier,
        partner_model1.participant_address,
        closed_block_number,
    )
    iteration = channel.handle_channel_closed(channel_state, state_change)
    assert not iteration.events


def test_channelstate_withdraw():
    """Event close must be properly handled if there are no locks to unlock"""
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 10
    lock_expiration = 100
    lock_secret = sha3(b'test_channelstate_mediatedtransfer_overspent')
    lock_hashlock = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )

    nonce = 1
    transferred_amount = 0
    receive_mediatedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, msg = channel.handle_receive_mediatedtransfer(
        channel_state,
        receive_mediatedtransfer,
    )
    assert is_valid, msg

    channel.register_secret(channel_state, lock_secret, lock_hashlock)

    # If the channel is closed, withdraw must be done even if the lock is not
    # at risk of expiring
    closed_block_number = lock_expiration - channel_state.reveal_timeout - 1
    state_change = ContractReceiveChannelClosed(
        channel_state.identifier,
        partner_model1.participant_address,
        closed_block_number,
    )
    iteration = channel.handle_channel_closed(channel_state, state_change)
    assert must_contain_entry(iteration.events, ContractSendChannelWithdraw, {})
