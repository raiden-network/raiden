# pylint: disable=too-many-locals,too-many-statements,too-many-lines
import random
from collections import namedtuple
from copy import deepcopy
from itertools import cycle

import pytest
import structlog

from raiden.constants import UINT64_MAX
from raiden.messages import DirectTransfer, Secret
from raiden.settings import DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import (
    HOP1,
    UNIT_CHAIN_ID,
    UNIT_REGISTRY_IDENTIFIER,
    UNIT_SECRET,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_SENDER,
    UNIT_TRANSFER_TARGET,
    make_secret,
)
from raiden.tests.utils.transfer import make_receive_transfer_mediated
from raiden.transfer import channel
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelUpdateTransfer,
    EventPaymentReceivedSuccess,
    EventTransferReceivedInvalidDirectTransfer,
)
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.merkle_tree import (
    LEAVES,
    MERKLEROOT,
    compute_layers,
    merkle_leaves_from_packed_data,
    merkleroot,
)
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSING,
    EMPTY_MERKLE_ROOT,
    HashTimeLockState,
    MerkleTreeState,
    NettingChannelEndState,
    NettingChannelState,
    TransactionChannelNewBalance,
    TransactionExecutionStatus,
    UnlockPartialProofState,
    balanceproof_from_envelope,
)
from raiden.transfer.state_change import (
    ActionChannelClose,
    Block,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveUpdateTransfer,
    ReceiveTransferDirect,
    ReceiveUnlock,
)
from raiden.utils import privatekey_to_address, random_secret, sha3

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


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


def create_model(balance, merkletree_width=0):
    privkey, address = factories.make_privkey_address()

    merkletree_leaves = [random_secret() for _ in range(merkletree_width)]

    our_model = PartnerStateModel(
        participant_address=address,
        amount_locked=0,
        balance=balance,
        distributable=balance,
        next_nonce=1,
        merkletree_leaves=merkletree_leaves,
        contract_balance=balance,
    )

    return our_model, privkey


def create_channel_end_state_from_model(model):
    state = NettingChannelEndState(model.participant_address, model.balance)
    if model.merkletree_leaves:
        state.merkletree = MerkleTreeState(compute_layers(model.merkletree_leaves))
    return state


def create_channel_from_models(our_model, partner_model):
    """Utility to instantiate state objects used throughout the tests."""
    our_state = create_channel_end_state_from_model(our_model)
    partner_state = create_channel_end_state_from_model(partner_model)

    identifier = factories.make_channel_identifier()
    token_address = factories.make_address()
    payment_network_identifier = factories.make_payment_network_identifier()
    token_network_identifier = factories.make_address()
    reveal_timeout = 10
    settle_timeout = 100
    opened_transaction = TransactionExecutionStatus(
        None,
        1,
        TransactionExecutionStatus.SUCCESS,
    )
    closed_transaction = None
    settled_transaction = None

    channel_state = NettingChannelState(
        identifier=identifier,
        chain_id=UNIT_CHAIN_ID,
        token_address=token_address,
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=token_network_identifier,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=opened_transaction,
        close_transaction=closed_transaction,
        settle_transaction=settled_transaction,
    )

    assert channel_state.our_total_deposit == our_model.contract_balance
    assert channel_state.partner_total_deposit == partner_model.contract_balance

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
        locksroot=EMPTY_MERKLE_ROOT,
        token_network_identifier=UNIT_REGISTRY_IDENTIFIER,
        locked_amount=None,
        chain_id=UNIT_CHAIN_ID,
):

    address = privatekey_to_address(privkey.secret)
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError('Private key does not match any of the participants.')

    if locked_amount is None:
        locked_amount = channel.get_amount_locked(channel_state.our_state)

    message_identifier = random.randint(0, UINT64_MAX)
    payment_identifier = nonce
    mediated_transfer_msg = DirectTransfer(
        chain_id=chain_id,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=channel_state.token_network_identifier,
        token=channel_state.token_address,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=channel_state.partner_state.address,
        locksroot=locksroot,
    )
    mediated_transfer_msg.sign(privkey)

    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)

    receive_directtransfer = ReceiveTransferDirect(
        token_network_identifier,
        message_identifier,
        payment_identifier,
        balance_proof,
    )

    return receive_directtransfer


def test_new_end_state():
    """Test the defaults for an end state object."""
    balance1 = 101
    node_address = factories.make_address()
    end_state = NettingChannelEndState(node_address, balance1)

    lock_secret = sha3(b'test_end_state')
    lock_secrethash = sha3(lock_secret)

    assert channel.is_lock_pending(end_state, lock_secrethash) is False
    assert channel.is_lock_locked(end_state, lock_secrethash) is False
    assert channel.get_next_nonce(end_state) == 1
    assert channel.get_amount_locked(end_state) == 0
    assert merkleroot(end_state.merkletree) == EMPTY_MERKLE_ROOT

    assert not end_state.secrethashes_to_lockedlocks
    assert not end_state.secrethashes_to_unlockedlocks
    assert not end_state.secrethashes_to_onchain_unlockedlocks


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
    deposit_block_number = 10
    block_number = deposit_block_number + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK + 1

    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    deposit_amount = 10
    balance1_new = our_model1.balance + deposit_amount

    deposit_transaction = TransactionChannelNewBalance(
        our_model1.participant_address,
        balance1_new,
        deposit_block_number,
    )
    state_change = ContractReceiveChannelNewBalance(
        factories.make_transaction_hash(),
        channel_state.token_network_identifier,
        channel_state.identifier,
        deposit_transaction,
    )

    pseudo_random_generator = random.Random()
    iteration = channel.state_transition(
        deepcopy(channel_state),
        state_change,
        pseudo_random_generator,
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
    deposit_block_number = 10
    block_number = deposit_block_number + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK + 1

    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    amount = 10
    balance1_new = our_model1.balance - amount

    deposit_transaction = TransactionChannelNewBalance(
        our_model1.participant_address,
        balance1_new,
        deposit_block_number,
    )
    state_change = ContractReceiveChannelNewBalance(
        factories.make_transaction_hash(),
        channel_state.token_network_identifier,
        channel_state.identifier,
        deposit_transaction,
    )

    pseudo_random_generator = random.Random()
    iteration = channel.state_transition(
        deepcopy(channel_state),
        state_change,
        pseudo_random_generator,
        block_number,
    )
    new_state = iteration.new_state

    assert_partner_state(new_state.our_state, new_state.partner_state, our_model1)
    assert_partner_state(new_state.partner_state, new_state.our_state, partner_model1)


def test_channelstate_repeated_contract_balance():
    """Handling the same blockchain event multiple times must change the
    balance only once.
    """
    deposit_block_number = 10
    block_number = deposit_block_number + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK + 1

    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    deposit_amount = 10
    balance1_new = our_model1.balance + deposit_amount

    deposit_transaction = TransactionChannelNewBalance(
        our_model1.participant_address,
        balance1_new,
        deposit_block_number,
    )
    state_change = ContractReceiveChannelNewBalance(
        factories.make_transaction_hash(),
        channel_state.token_network_identifier,
        channel_state.identifier,
        deposit_transaction,
    )

    our_model2 = our_model1._replace(
        balance=balance1_new,
        distributable=balance1_new,
        contract_balance=balance1_new,
    )
    partner_model2 = partner_model1
    pseudo_random_generator = random.Random()

    for _ in range(10):
        iteration = channel.state_transition(
            deepcopy(channel_state),
            state_change,
            pseudo_random_generator,
            block_number,
        )
        new_state = iteration.new_state

        assert_partner_state(new_state.our_state, new_state.partner_state, our_model2)
        assert_partner_state(new_state.partner_state, new_state.our_state, partner_model2)


def test_deposit_must_wait_for_confirmation():
    block_number = 10
    confirmed_deposit_block_number = block_number + DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK + 1

    our_model1, _ = create_model(0)
    partner_model1, _ = create_model(0)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    deposit_amount = 10
    balance1_new = our_model1.balance + deposit_amount
    our_model2 = our_model1._replace(
        balance=balance1_new,
        distributable=balance1_new,
        contract_balance=balance1_new,
    )
    partner_model2 = partner_model1

    assert channel_state.our_state.contract_balance == 0
    assert channel_state.partner_state.contract_balance == 0

    deposit_transaction = TransactionChannelNewBalance(
        channel_state.our_state.address,
        deposit_amount,
        block_number,
    )
    new_balance = ContractReceiveChannelNewBalance(
        factories.make_transaction_hash(),
        channel_state.token_network_identifier,
        channel_state.identifier,
        deposit_transaction,
    )
    pseudo_random_generator = random.Random()
    iteration = channel.state_transition(
        deepcopy(channel_state),
        new_balance,
        pseudo_random_generator,
        block_number,
    )
    unconfirmed_state = iteration.new_state

    for block_number in range(block_number, confirmed_deposit_block_number):
        unconfirmed_block = Block(
            block_number=block_number,
            gas_limit=1,
            block_hash=factories.make_transaction_hash(),
        )
        iteration = channel.state_transition(
            deepcopy(unconfirmed_state),
            unconfirmed_block,
            pseudo_random_generator,
            block_number,
        )
        unconfirmed_state = iteration.new_state

        assert_partner_state(
            unconfirmed_state.our_state,
            unconfirmed_state.partner_state,
            our_model1,
        )
        assert_partner_state(
            unconfirmed_state.partner_state,
            unconfirmed_state.our_state,
            partner_model1,
        )

    confirmed_block = Block(
        block_number=confirmed_deposit_block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = channel.state_transition(
        deepcopy(unconfirmed_state),
        confirmed_block,
        pseudo_random_generator,
        confirmed_deposit_block_number,
    )
    confirmed_state = iteration.new_state

    assert_partner_state(confirmed_state.our_state, confirmed_state.partner_state, our_model2)
    assert_partner_state(confirmed_state.partner_state, confirmed_state.our_state, partner_model2)


def test_channelstate_send_lockedtransfer():
    """Sending a mediated transfer must update the participant state.

    This tests only the state of the sending node, without synchronisation.
    """
    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_end_state')
    lock_secrethash = sha3(lock_secret)

    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    payment_identifier = 1
    message_identifier = random.randint(0, UINT64_MAX)
    transfer_target = factories.make_address()
    transfer_initiator = factories.make_address()

    channel.send_lockedtransfer(
        channel_state,
        transfer_initiator,
        transfer_target,
        lock_amount,
        message_identifier,
        payment_identifier,
        lock_expiration,
        lock_secrethash,
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
    payment_identifier = 1
    message_identifier = random.randint(0, UINT64_MAX)
    channel.send_directtransfer(
        channel_state,
        amount,
        message_identifier,
        payment_identifier,
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


def test_channelstate_receive_lockedtransfer():
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
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
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
    channel.register_secret(channel_state, lock_secret, lock_secrethash)

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)

    # Step 3: Simulate unlocking the lock
    # - Update the balances
    transferred_amount = 0
    message_identifier = random.randint(0, UINT64_MAX)
    token_network_identifier = channel_state.token_network_identifier
    secret_message = Secret(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=1,
        nonce=2,
        token_network_address=token_network_identifier,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount + lock_amount,
        locked_amount=0,
        locksroot=EMPTY_MERKLE_ROOT,
        secret=lock_secret,
    )
    secret_message.sign(privkey2)
    # Let's also create an invalid secret to test unlock with invalid chain id
    invalid_secret_message = Secret(
        chain_id=UNIT_CHAIN_ID + 1,
        message_identifier=message_identifier,
        payment_identifier=1,
        nonce=2,
        token_network_address=token_network_identifier,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount + lock_amount,
        locked_amount=0,
        locksroot=EMPTY_MERKLE_ROOT,
        secret=lock_secret,
    )
    invalid_secret_message.sign(privkey2)

    balance_proof = balanceproof_from_envelope(secret_message)
    unlock_state_change = ReceiveUnlock(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=lock_secret,
        balance_proof=balance_proof,
    )

    # First test that unlock with invalid chain_id fails
    invalid_balance_proof = balanceproof_from_envelope(invalid_secret_message)
    invalid_unlock_state_change = ReceiveUnlock(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=lock_secret,
        balance_proof=invalid_balance_proof,
    )
    is_valid, _, _ = channel.handle_unlock(channel_state, invalid_unlock_state_change)
    assert not is_valid, (
        "Unlock message with chain_id different than the "
        "channel's should fail"
    )

    is_valid, _, msg = channel.handle_unlock(channel_state, unlock_state_change)
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
    receive_lockedtransfer = make_receive_transfer_direct(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
    )

    is_valid, _ = channel.is_valid_directtransfer(
        receive_lockedtransfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )
    assert not is_valid, 'message is invalid because it is spending more than the distributable'

    iteration = channel.handle_receive_directtransfer(
        channel_state,
        receive_lockedtransfer,
    )

    assert must_contain_entry(iteration.events, EventTransferReceivedInvalidDirectTransfer, {})
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_directtransfer_invalid_chainid():
    """Receiving a direct transfer with a chain_id different than the channel's
    chain_id should be ignored
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)

    nonce = 1
    transferred_amount = distributable - 1
    receive_lockedtransfer = make_receive_transfer_direct(
        channel_state=channel_state,
        privkey=privkey2,
        nonce=nonce,
        transferred_amount=transferred_amount,
        chain_id=UNIT_CHAIN_ID + 2,
    )

    is_valid, _ = channel.is_valid_directtransfer(
        receive_lockedtransfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )
    assert not is_valid, (
        'message is invalid because it contains different chain id than the channel'
    )

    iteration = channel.handle_receive_directtransfer(
        channel_state,
        receive_lockedtransfer,
    )

    assert must_contain_entry(iteration.events, EventTransferReceivedInvalidDirectTransfer, {})
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_lockedtransfer_overspent():
    """Receiving a lock with an amount large than distributable must be
    ignored.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)

    lock_amount = distributable + 1
    lock_expiration = 10
    lock_secrethash = sha3(b'test_channelstate_lockedtransfer_overspent')
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _, _ = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
    )
    assert not is_valid, 'message is invalid because it is spending more than the distributable'

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_lockedtransfer_invalid_chainid():
    """Receiving a locked transfer with chain_id different from the channel's
    chain_id should be ignored
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    distributable = channel.get_distributable(channel_state.partner_state, channel_state.our_state)

    lock_amount = distributable - 1
    lock_expiration = 10
    lock_secrethash = sha3(b'test_channelstate_lockedtransfer_overspent')
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
        chain_id=UNIT_CHAIN_ID + 1,
    )

    is_valid, _, _ = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
    )
    assert not is_valid, (
        'message is invalid because it uses different chain_id than the channel'
    )

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model1)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model1)


def test_channelstate_lockedtransfer_overspend_with_multiple_pending_transfers():
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
    lock1_secrethash = sha3(b'test_receive_cannot_overspend_with_multiple_pending_transfers1')
    lock1 = HashTimeLockState(
        lock1_amount,
        lock1_expiration,
        lock1_secrethash,
    )

    nonce1 = 1
    transferred_amount = 0
    receive_lockedtransfer1 = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce1,
        transferred_amount,
        lock1,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer1,
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
    lock2_secrethash = sha3(b'test_receive_cannot_overspend_with_multiple_pending_transfers2')
    lock2 = HashTimeLockState(
        lock2_amount,
        lock2_expiration,
        lock2_secrethash,
    )
    leaves = [lock1.lockhash, lock2.lockhash]

    nonce2 = 2
    receive_lockedtransfer2 = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce2,
        transferred_amount,
        lock2,
        merkletree_leaves=leaves,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer2,
    )
    assert not is_valid, 'message is invalid because its expending more than the distributable'

    # The overspending transfer must be ignored
    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model2)
    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model2)


def test_invalid_timeouts():
    token_address = factories.make_address()
    token_network_identifier = factories.make_address()
    payment_network_identifier = factories.make_payment_network_identifier()
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
            identifier=identifier,
            chain_id=UNIT_CHAIN_ID,
            token_address=token_address,
            payment_network_identifier=payment_network_identifier,
            token_network_identifier=token_network_identifier,
            reveal_timeout=large_reveal_timeout,
            settle_timeout=small_settle_timeout,
            our_state=our_state,
            partner_state=partner_state,
            open_transaction=opened_transaction,
            close_transaction=closed_transaction,
            settle_transaction=settled_transaction,
        )

    # TypeError: 'a', [], {}
    for invalid_value in (-1, 0, 1.1, 1.0):
        with pytest.raises(ValueError):
            NettingChannelState(
                identifier=identifier,
                chain_id=UNIT_CHAIN_ID,
                token_address=token_address,
                payment_network_identifier=payment_network_identifier,
                token_network_identifier=token_network_identifier,
                reveal_timeout=invalid_value,
                settle_timeout=settle_timeout,
                our_state=our_state,
                partner_state=partner_state,
                open_transaction=opened_transaction,
                close_transaction=closed_transaction,
                settle_transaction=settled_transaction,
            )

        with pytest.raises(ValueError):
            NettingChannelState(
                identifier=identifier,
                chain_id=UNIT_CHAIN_ID,
                token_address=token_address,
                payment_network_identifier=payment_network_identifier,
                token_network_identifier=token_network_identifier,
                reveal_timeout=reveal_timeout,
                settle_timeout=invalid_value,
                our_state=our_state,
                partner_state=partner_state,
                open_transaction=opened_transaction,
                close_transaction=closed_transaction,
                settle_transaction=settled_transaction,
            )


def test_interwoven_transfers():
    """Can keep doing transactions even if not all secrets have been released."""
    number_of_transfers = 100
    balance_for_all_transfers = 11 * number_of_transfers

    lock_amounts = cycle([1, 3, 5, 7, 11])
    lock_secrets = [
        make_secret(i)
        for i in range(number_of_transfers)
    ]

    our_model, _ = create_model(70)
    partner_model, privkey2 = create_model(balance_for_all_transfers)
    channel_state = create_channel_from_models(our_model, partner_model)

    block_number = 1000
    nonce = 0
    transferred_amount = 0
    locked_amount = 0
    our_model_current = our_model
    partner_model_current = partner_model
    token_network_address = channel_state.token_network_identifier

    for i, (lock_amount, lock_secret) in enumerate(zip(lock_amounts, lock_secrets)):
        nonce += 1
        block_number += 1
        locked_amount += lock_amount

        lock_expiration = block_number + channel_state.settle_timeout - 1
        lock_secrethash = sha3(lock_secret)
        lock = HashTimeLockState(
            lock_amount,
            lock_expiration,
            lock_secrethash,
        )

        merkletree_leaves = list(partner_model_current.merkletree_leaves)
        merkletree_leaves.append(lock.lockhash)

        partner_model_current = partner_model_current._replace(
            distributable=partner_model_current.distributable - lock_amount,
            amount_locked=partner_model_current.amount_locked + lock_amount,
            next_nonce=partner_model_current.next_nonce + 1,
            merkletree_leaves=merkletree_leaves,
        )

        receive_lockedtransfer = make_receive_transfer_mediated(
            channel_state,
            privkey2,
            nonce,
            transferred_amount,
            lock,
            merkletree_leaves=merkletree_leaves,
            locked_amount=locked_amount,
        )

        is_valid, _, msg = channel.handle_receive_lockedtransfer(
            channel_state,
            receive_lockedtransfer,
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
            locked_amount -= lock_amount

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

            message_identifier = random.randint(0, UINT64_MAX)
            secret_message = Secret(
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
            )
            secret_message.sign(privkey2)

            balance_proof = balanceproof_from_envelope(secret_message)
            unlock_state_change = ReceiveUnlock(
                message_identifier=random.randint(0, UINT64_MAX),
                secret=lock_secret,
                balance_proof=balance_proof,
            )

            is_valid, _, msg = channel.handle_unlock(channel_state, unlock_state_change)
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


def test_channel_never_expires_lock_with_secret_onchain():
    """ Send a mediated transfer and register secret on chain.
    The lock must be moved into secrethashes_to_onchain_unlockedlocks
    """
    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_end_state')
    lock_secrethash = sha3(lock_secret)

    lock = HashTimeLockState(
        amount=lock_amount,
        expiration=lock_expiration,
        secrethash=lock_secrethash,
    )

    payment_identifier = 1
    message_identifier = random.randint(0, UINT64_MAX)
    transfer_target = factories.make_address()
    transfer_initiator = factories.make_address()

    channel.send_lockedtransfer(
        channel_state=channel_state,
        initiator=transfer_initiator,
        target=transfer_target,
        amount=lock_amount,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        expiration=lock_expiration,
        secrethash=lock_secrethash,
    )

    assert lock.secrethash in channel_state.our_state.secrethashes_to_lockedlocks

    channel.register_onchain_secret(
        channel_state=channel_state,
        secret=lock_secret,
        secrethash=lock.secrethash,
        delete_lock=True,
    )

    assert lock.secrethash not in channel_state.our_state.secrethashes_to_lockedlocks
    assert lock.secrethash in channel_state.our_state.secrethashes_to_onchain_unlockedlocks


def test_channel_must_never_expire_locks_with_onchain_secret():
    """ A transfer is received and the secret is registered on chain.
    This means that any lock expired messages should not be accepted.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    block_number = 100

    lock_amount = 10
    lock_expiration = block_number - 10
    lock_secret = b'test_channel_must_accept_expired_locks'
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        amount=lock_amount,
        expiration=lock_expiration,
        secrethash=lock_secrethash,
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
        channel_state=channel_state,
        mediated_transfer=receive_lockedtransfer,
    )
    assert is_valid, msg

    assert lock.secrethash in channel_state.partner_state.secrethashes_to_lockedlocks

    channel.register_onchain_secret(
        channel_state=channel_state,
        secret=lock_secret,
        secrethash=lock_secrethash,
        delete_lock=False,
    )

    lock_expired = ReceiveLockExpired(
        channel_state.partner_state.address,
        receive_lockedtransfer.balance_proof,
        lock_secrethash,
        1,
    )

    is_valid, _, _ = channel.is_valid_lock_expired(
        lock_expired,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )

    assert not is_valid

    channel.handle_receive_lock_expired(
        channel_state,
        lock_expired,
    )

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
    channel_state = create_channel_from_models(our_model1, partner_model1)

    block_number = 100

    lock_amount = 10
    lock_expiration = block_number - 10
    lock_secrethash = sha3(b'test_channel_must_accept_expired_locks')
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
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


def test_receive_lockedtransfer_before_deposit():
    """Regression test that ensures we accept incoming mediated transfers, even if we don't have
    any balance on the channel.
    """
    our_model1, _ = create_model(0)  # our deposit is 0
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_end_state')
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
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
    assert must_contain_entry(iteration.events, EventPaymentReceivedSuccess, {})


def test_channelstate_unlock_without_locks():
    """Event close must be properly handled if there are no locks to unlock"""
    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    closed_block_number = 77
    state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        our_model1.participant_address,
        channel_state.token_network_identifier,
        channel_state.identifier,
        closed_block_number,
    )
    iteration = channel.handle_channel_closed(channel_state, state_change)
    assert not iteration.events


def test_channelstate_get_unlock_proof():
    number_of_transfers = 100
    lock_amounts = cycle([1, 3, 5, 7, 11])
    lock_secrets = [
        make_secret(i)
        for i in range(number_of_transfers)
    ]

    block_number = 1000
    locked_amount = 0
    settle_timeout = 8
    merkletree_leaves = []
    locked_locks = {}
    unlocked_locks = {}

    for lock_amount, lock_secret in zip(lock_amounts, lock_secrets):
        block_number += 1
        locked_amount += lock_amount

        lock_expiration = block_number + settle_timeout
        lock_secrethash = sha3(lock_secret)
        lock = HashTimeLockState(
            lock_amount,
            lock_expiration,
            lock_secrethash,
        )

        merkletree_leaves.append(lock.lockhash)
        if random.randint(0, 1) == 0:
            locked_locks[lock_secrethash] = lock
        else:
            unlocked_locks[lock_secrethash] = UnlockPartialProofState(lock, lock_secret)

    end_state = NettingChannelEndState(HOP1, 300)
    end_state.secrethashes_to_lockedlocks = locked_locks
    end_state.secrethashes_to_unlockedlocks = unlocked_locks
    end_state.merkletree = MerkleTreeState(compute_layers(merkletree_leaves))

    unlock_proof = channel.get_batch_unlock(end_state)
    assert len(unlock_proof) == len(end_state.merkletree.layers[LEAVES])
    leaves_packed = b''.join(lock.encoded for lock in unlock_proof)

    recomputed_merkle_tree = MerkleTreeState(compute_layers(
        merkle_leaves_from_packed_data(leaves_packed),
    ))
    assert len(recomputed_merkle_tree.layers[LEAVES]) == len(end_state.merkletree.layers[LEAVES])

    computed_merkleroot = merkleroot(recomputed_merkle_tree)
    assert merkleroot(end_state.merkletree) == computed_merkleroot


def test_channelstate_unlock():
    """The node must call unlock after the channel is settled"""
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 10
    lock_expiration = 100
    lock_secret = sha3(b'test_channelstate_lockedtransfer_overspent')
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
    )
    assert is_valid, msg

    channel.register_secret(channel_state, lock_secret, lock_secrethash)

    closed_block_number = lock_expiration - channel_state.reveal_timeout - 1
    close_state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        partner_model1.participant_address,
        channel_state.token_network_identifier,
        channel_state.identifier,
        closed_block_number,
    )
    iteration = channel.handle_channel_closed(channel_state, close_state_change)
    assert not must_contain_entry(iteration.events, ContractSendChannelBatchUnlock, {})

    settle_block_number = lock_expiration + channel_state.reveal_timeout + 1
    settle_state_change = ContractReceiveChannelSettled(
        factories.make_transaction_hash(),
        channel_state.token_network_identifier,
        channel_state.identifier,
        settle_block_number,
    )
    iteration = channel.handle_channel_settled(
        channel_state,
        settle_state_change,
        settle_block_number,
    )
    assert must_contain_entry(iteration.events, ContractSendChannelBatchUnlock, {})


def test_refund_transfer_matches_received():
    amount = 30
    expiration = 50

    transfer = factories.make_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
    )

    refund_lower_expiration = factories.make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration - 1,
        UNIT_SECRET,
    )

    assert channel.refund_transfer_matches_received(refund_lower_expiration, transfer) is False

    refund_same_expiration = factories.make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
    )
    assert channel.refund_transfer_matches_received(refund_same_expiration, transfer) is True


def test_refund_transfer_does_not_match_received():
    amount = 30
    expiration = 50
    target = UNIT_TRANSFER_SENDER
    transfer = factories.make_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        target,
        expiration,
        UNIT_SECRET,
    )

    refund_from_target = factories.make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration - 1,
        UNIT_SECRET,
    )
    # target cannot refund
    assert not channel.refund_transfer_matches_received(refund_from_target, transfer)


def test_settle_transaction_must_be_sent_only_once():
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_settle_transaction_must_be_sent_only_once')
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
    )
    assert is_valid, msg

    channel.register_secret(channel_state, lock_secret, lock_secrethash)

    closed_block_number = lock_expiration - channel_state.reveal_timeout - 1
    close_state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        partner_model1.participant_address,
        channel_state.token_network_identifier,
        channel_state.identifier,
        closed_block_number,
    )
    iteration = channel.handle_channel_closed(channel_state, close_state_change)

    settle_block_number = lock_expiration + channel_state.reveal_timeout + 1
    settle_state_change = ContractReceiveChannelSettled(
        factories.make_transaction_hash(),
        channel_state.token_network_identifier,
        channel_state.identifier,
        settle_block_number,
    )
    iteration = channel.handle_channel_settled(
        channel_state,
        settle_state_change,
        settle_block_number,
    )
    assert must_contain_entry(iteration.events, ContractSendChannelBatchUnlock, {})

    iteration = channel.handle_channel_settled(
        channel_state,
        settle_state_change,
        settle_block_number,
    )
    msg = 'BatchUnlock must be sent only once, the second transaction will always fail'
    assert not must_contain_entry(iteration.events, ContractSendChannelBatchUnlock, {}), msg


def test_action_close_must_change_the_channel_state():
    """ A closed channel must not be used for transactions, even if the
    transaction was not confirmed on-chain.
    """
    our_model1, _ = create_model(70)
    partner_model1, _ = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    pseudo_random_generator = random.Random()
    block_number = 10
    state_change = ActionChannelClose(
        channel_state.token_network_identifier,
        channel_state.identifier,
    )
    iteration = channel.state_transition(
        channel_state,
        state_change,
        pseudo_random_generator,
        block_number,
    )
    assert channel.get_status(iteration.new_state) == CHANNEL_STATE_CLOSING


def test_update_must_be_called_if_close_lost_race():
    """ If both participants call close, the node that lost the transaction
    race must call updateTransfer.
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    lock_amount = 30
    lock_expiration = 10
    lock_secret = sha3(b'test_update_must_be_called_if_close_lost_race')
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    nonce = 1
    transferred_amount = 0
    receive_lockedtransfer = make_receive_transfer_mediated(
        channel_state,
        privkey2,
        nonce,
        transferred_amount,
        lock,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        channel_state,
        receive_lockedtransfer,
    )
    assert is_valid, msg

    pseudo_random_generator = random.Random()
    block_number = 10
    state_change = ActionChannelClose(
        channel_state.token_network_identifier,
        channel_state.identifier,
    )
    iteration = channel.state_transition(
        channel_state,
        state_change,
        pseudo_random_generator,
        block_number,
    )

    closed_block_number = 77
    state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        partner_model1.participant_address,
        channel_state.token_network_identifier,
        channel_state.identifier,
        closed_block_number,
    )
    iteration = channel.handle_channel_closed(channel_state, state_change)
    assert must_contain_entry(iteration.events, ContractSendChannelUpdateTransfer, {})


def test_update_transfer():
    """ This tests that receiving an update transfer event for a
    closed channel sets the update_transaction member
    """
    our_model1, _ = create_model(70)
    partner_model1, privkey2 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1)

    pseudo_random_generator = random.Random()
    block_number = 10
    state_change = ActionChannelClose(
        channel_state.token_network_identifier,
        channel_state.identifier,
    )
    iteration = channel.state_transition(
        channel_state,
        state_change,
        pseudo_random_generator,
        block_number,
    )

    # update_transaction in channel state should not be set
    channel_state = iteration.new_state
    assert channel_state.update_transaction is None

    closed_block_number = 15
    channel_close_state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        partner_model1.participant_address,
        channel_state.token_network_identifier,
        channel_state.identifier,
        closed_block_number,
    )
    iteration2 = channel.handle_channel_closed(
        channel_state,
        channel_close_state_change,
    )

    # update_transaction in channel state should not be set because there was no transfer
    channel_state = iteration2.new_state
    assert channel_state.update_transaction is None

    update_transfer_state_change = ContractReceiveUpdateTransfer(
        partner_model1.participant_address,
        channel_state.token_network_identifier,
        channel_state.identifier,
        23,
    )

    update_block_number = 20
    iteration3 = channel.handle_channel_updated_transfer(
        channel_state,
        update_transfer_state_change,
        update_block_number,
    )

    # now update_transaction in channel state should be set
    channel_state = iteration3.new_state
    assert channel_state.update_transaction == TransactionExecutionStatus(
        started_block_number=None,
        finished_block_number=update_block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )
