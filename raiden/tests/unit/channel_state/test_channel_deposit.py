# pylint: disable=too-many-locals,too-many-statements,too-many-lines
import random

from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, MediationFeeConfig
from raiden.tests.unit.channel_state.utils import (
    assert_partner_state,
    create_channel_from_models,
    create_model,
)
from raiden.tests.utils.factories import make_address, make_block_hash, make_transaction_hash
from raiden.transfer import channel
from raiden.transfer.state import NettingChannelEndState, TransactionChannelDeposit
from raiden.transfer.state_change import ContractReceiveChannelDeposit
from raiden.utils.copy import deepcopy


def test_endstate_update_contract_balance():
    """The balance must be monotonic."""
    balance1 = 101
    node_address = make_address()

    end_state = NettingChannelEndState(node_address, balance1)
    assert end_state.contract_balance == balance1

    channel.update_contract_balance(end_state, balance1 - 10)
    assert end_state.contract_balance == balance1

    channel.update_contract_balance(end_state, balance1 + 10)
    assert end_state.contract_balance == balance1 + 10


def test_channelstate_update_contract_balance():
    """A blockchain event for a new balance must increase the respective
    participants balance and trigger a fee update
    """
    deposit_block_number = 10
    block_number = deposit_block_number + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    block_hash = make_block_hash()

    our_model1, _ = create_model(70)
    partner_model1, partner_pkey1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_pkey1)

    deposit_amount = 10
    balance1_new = our_model1.balance + deposit_amount

    deposit_transaction = TransactionChannelDeposit(
        our_model1.participant_address, balance1_new, deposit_block_number
    )
    state_change = ContractReceiveChannelDeposit(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        deposit_transaction=deposit_transaction,
        block_number=block_number,
        block_hash=block_hash,
        fee_config=MediationFeeConfig(),
    )

    iteration = channel.state_transition(
        channel_state=deepcopy(channel_state),
        state_change=state_change,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=random.Random(),
    )
    new_state = iteration.new_state

    our_model2 = our_model1._replace(
        balance=balance1_new, distributable=balance1_new, contract_balance=balance1_new
    )
    partner_model2 = partner_model1

    assert_partner_state(new_state.our_state, new_state.partner_state, our_model2)
    assert_partner_state(new_state.partner_state, new_state.our_state, partner_model2)


def test_channelstate_decreasing_contract_balance():
    """A blockchain event for a new balance that decrease the balance must be
    ignored.
    """
    deposit_block_number = 10
    block_number = deposit_block_number + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    deposit_block_hash = make_block_hash()

    our_model1, _ = create_model(70)
    partner_model1, partner_pkey1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_pkey1)

    amount = 10
    balance1_new = our_model1.balance - amount

    deposit_transaction = TransactionChannelDeposit(
        our_model1.participant_address, balance1_new, deposit_block_number
    )
    state_change = ContractReceiveChannelDeposit(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        deposit_transaction=deposit_transaction,
        block_number=deposit_block_number,
        block_hash=deposit_block_hash,
        fee_config=MediationFeeConfig(),
    )

    iteration = channel.state_transition(
        channel_state=deepcopy(channel_state),
        state_change=state_change,
        block_number=block_number,
        block_hash=make_block_hash(),
        pseudo_random_generator=random.Random(),
    )
    new_state = iteration.new_state

    assert_partner_state(new_state.our_state, new_state.partner_state, our_model1)
    assert_partner_state(new_state.partner_state, new_state.our_state, partner_model1)


def test_channelstate_repeated_contract_balance():
    """Handling the same blockchain event multiple times must change the
    balance only once.
    """
    deposit_block_number = 10
    block_number = deposit_block_number + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1
    deposit_block_hash = make_block_hash()

    our_model1, _ = create_model(70)
    partner_model1, partner_pkey1 = create_model(100)
    channel_state = create_channel_from_models(our_model1, partner_model1, partner_pkey1)

    deposit_amount = 10
    balance1_new = our_model1.balance + deposit_amount

    deposit_transaction = TransactionChannelDeposit(
        our_model1.participant_address, balance1_new, deposit_block_number
    )
    state_change = ContractReceiveChannelDeposit(
        transaction_hash=make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        deposit_transaction=deposit_transaction,
        block_number=deposit_block_number,
        block_hash=deposit_block_hash,
        fee_config=MediationFeeConfig(),
    )

    our_model2 = our_model1._replace(
        balance=balance1_new, distributable=balance1_new, contract_balance=balance1_new
    )
    partner_model2 = partner_model1

    for _ in range(10):
        iteration = channel.state_transition(
            channel_state=deepcopy(channel_state),
            state_change=state_change,
            block_number=block_number,
            block_hash=make_block_hash(),
            pseudo_random_generator=random.Random(),
        )
        new_state = iteration.new_state

        assert_partner_state(new_state.our_state, new_state.partner_state, our_model2)
        assert_partner_state(new_state.partner_state, new_state.our_state, partner_model2)
