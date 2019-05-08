from copy import deepcopy

import pytest

from raiden.constants import EMPTY_MERKLE_ROOT
from raiden.settings import GAS_LIMIT
from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    HOP1,
    HOP2,
    UNIT_CHANNEL_ID,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    make_block_hash,
)
from raiden.transfer.channel import compute_merkletree_with
from raiden.transfer.events import ContractSendChannelBatchUnlock
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.merkle_tree import merkleroot
from raiden.transfer.node import (
    get_networks,
    handle_new_token_network,
    is_transaction_effect_satisfied,
    maybe_add_tokennetwork,
    state_transition,
    subdispatch_initiatortask,
    subdispatch_targettask,
    subdispatch_to_paymenttask,
)
from raiden.transfer.state import (
    BalanceProofSignedState,
    PaymentNetworkState,
    RouteState,
    TargetTask,
    TokenNetworkState,
    make_empty_merkle_tree,
)
from raiden.transfer.state_change import (
    ActionNewTokenNetwork,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelSettled,
)


def test_is_transaction_effect_satisfied(
    chain_state, token_network_address, netting_channel_state
):
    canonical_identifier = netting_channel_state.canonical_identifier
    assert token_network_address == canonical_identifier.token_network_address
    transaction = ContractSendChannelBatchUnlock(
        canonical_identifier=canonical_identifier,
        sender=netting_channel_state.partner_state.address,
        triggered_by_block_hash=make_block_hash(),
    )
    state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=UNIT_SECRETHASH,
        canonical_identifier=canonical_identifier,
        receiver=HOP1,
        sender=HOP2,
        locksroot=EMPTY_MERKLE_ROOT,
        unlocked_amount=0,
        returned_tokens=0,
        block_number=1,
        block_hash=make_block_hash(),
    )
    # unlock for a channel in which this node is not a participant must return False
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    # now call normally with us being the partner and not the participant
    state_change.sender = netting_channel_state.partner_state.address
    state_change.receiver = netting_channel_state.our_state.address
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)
    # finally call with us being the participant and not the partner which should check out
    state_change.receiver = netting_channel_state.partner_state.address
    state_change.sender = netting_channel_state.our_state.address

    # ContractSendChannelBatchUnlock would only be satisfied if both sides are unlocked
    # and if the channel was cleared
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    channel_settled = ContractReceiveChannelSettled(
        transaction_hash=bytes(32),
        canonical_identifier=canonical_identifier,
        our_onchain_locksroot=EMPTY_MERKLE_ROOT,
        partner_onchain_locksroot=EMPTY_MERKLE_ROOT,
        block_number=1,
        block_hash=make_block_hash(),
    )

    iteration = state_transition(chain_state=chain_state, state_change=channel_settled)

    assert is_transaction_effect_satisfied(iteration.new_state, transaction, state_change)


def test_get_networks(chain_state, token_network_id):
    orig_chain_state = deepcopy(chain_state)
    token_address = factories.make_address()
    payment_network_empty = PaymentNetworkState(
        address=factories.make_address(), token_network_list=[]
    )
    chain_state.identifiers_to_paymentnetworks[
        payment_network_empty.address
    ] = payment_network_empty
    assert get_networks(
        chain_state=chain_state,
        payment_network_identifier=payment_network_empty.address,
        token_address=token_address,
    ) == (payment_network_empty, None)

    chain_state = orig_chain_state
    token_network = TokenNetworkState(address=token_network_id, token_address=token_address)
    payment_network = PaymentNetworkState(
        address=factories.make_address(), token_network_list=[token_network]
    )
    chain_state.identifiers_to_paymentnetworks[payment_network.address] = payment_network
    assert get_networks(
        chain_state=chain_state,
        payment_network_identifier=payment_network.address,
        token_address=token_address,
    ) == (payment_network, token_network)


def test_subdispatch_invalid_initiatortask(chain_state, token_network_id):
    subtask = object()
    chain_state.payment_mapping.secrethashes_to_task[UNIT_SECRETHASH] = subtask
    transition_result = subdispatch_initiatortask(
        chain_state=chain_state,
        state_change=None,
        token_network_identifier=token_network_id,
        secrethash=UNIT_SECRETHASH,
    )
    assert transition_result.new_state == chain_state
    assert not transition_result.events


def test_subdispatch_invalid_targettask(chain_state, token_network_id):
    subtask = object()
    chain_state.payment_mapping.secrethashes_to_task[UNIT_SECRETHASH] = subtask
    transition_result = subdispatch_targettask(
        chain_state=chain_state,
        state_change=None,
        token_network_identifier=token_network_id,
        channel_identifier=UNIT_CHANNEL_ID,
        secrethash=UNIT_SECRETHASH,
    )
    assert transition_result.new_state == chain_state
    assert not transition_result.events


@pytest.mark.parametrize("partner", [factories.UNIT_TRANSFER_SENDER])
def test_subdispatch_to_paymenttask_target(chain_state, netting_channel_state):
    target_state = TargetTransferState(
        route=RouteState(
            node_address=netting_channel_state.partner_state.address,
            channel_identifier=netting_channel_state.canonical_identifier.channel_identifier,
        ),
        transfer=factories.create(factories.LockedTransferSignedStateProperties()),
        secret=UNIT_SECRET,
    )
    subtask = TargetTask(
        canonical_identifier=netting_channel_state.canonical_identifier, target_state=target_state
    )
    chain_state.payment_mapping.secrethashes_to_task[UNIT_SECRETHASH] = subtask

    lock = factories.HashTimeLockState(amount=0, expiration=2, secrethash=UNIT_SECRETHASH)

    netting_channel_state.partner_state.secrethashes_to_lockedlocks[UNIT_SECRETHASH] = lock
    netting_channel_state.partner_state.merkletree = compute_merkletree_with(
        merkletree=make_empty_merkle_tree(), lockhash=lock.lockhash
    )
    state_change = Block(
        block_number=chain_state.block_number,
        gas_limit=GAS_LIMIT,
        block_hash=chain_state.block_hash,
    )
    transition_result = subdispatch_to_paymenttask(
        chain_state=chain_state, state_change=state_change, secrethash=UNIT_SECRETHASH
    )
    assert transition_result.events == []
    assert transition_result.new_state == chain_state

    chain_state.block_number = 20

    balance_proof: BalanceProofSignedState = factories.create(
        factories.BalanceProofSignedStateProperties(
            canonical_identifier=netting_channel_state.canonical_identifier,
            sender=netting_channel_state.partner_state.address,
            transferred_amount=0,
            pkey=factories.UNIT_TRANSFER_PKEY,
            locksroot=merkleroot(make_empty_merkle_tree()),
        )
    )
    state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=UNIT_SECRETHASH,
        message_identifier=factories.make_message_identifier(),
    )
    transition_result = subdispatch_to_paymenttask(
        chain_state=chain_state, state_change=state_change, secrethash=UNIT_SECRETHASH
    )
    msg = "ReceiveLockExpired should have cleared the task"
    assert UNIT_SECRETHASH not in chain_state.payment_mapping.secrethashes_to_task, msg
    assert len(transition_result.events), "ReceiveLockExpired should generate events"
    assert transition_result.new_state == chain_state


def test_maybe_add_tokennetwork_unknown_payment_network(chain_state, token_network_id):
    payment_network_identifier = factories.make_address()
    token_address = factories.make_address()
    token_network = TokenNetworkState(address=token_network_id, token_address=token_address)
    msg = "test state invalid, payment_network already in chain_state"
    assert payment_network_identifier not in chain_state.identifiers_to_paymentnetworks, msg
    maybe_add_tokennetwork(
        chain_state=chain_state,
        payment_network_identifier=payment_network_identifier,
        token_network_state=token_network,
    )
    # new payment network should have been added to chain_state
    payment_network_state = chain_state.identifiers_to_paymentnetworks[payment_network_identifier]
    assert payment_network_state.address == payment_network_identifier


def test_handle_new_token_network(chain_state, token_network_id):
    token_address = factories.make_address()
    token_network = TokenNetworkState(address=token_network_id, token_address=token_address)
    payment_network_identifier = factories.make_address()
    state_change = ActionNewTokenNetwork(
        payment_network_identifier=payment_network_identifier, token_network=token_network
    )
    transition_result = handle_new_token_network(
        chain_state=chain_state, state_change=state_change
    )
    new_chain_state = transition_result.new_state
    payment_network = new_chain_state.identifiers_to_paymentnetworks[payment_network_identifier]
    assert payment_network.address == payment_network_identifier
    assert not transition_result.events
    assert get_networks(
        chain_state=chain_state,
        payment_network_identifier=payment_network_identifier,
        token_address=token_address,
    ) == (payment_network, token_network)
