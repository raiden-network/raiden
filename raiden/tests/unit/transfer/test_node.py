import pytest

import raiden.transfer.node
from raiden.constants import LOCKSROOT_OF_NO_LOCKS
from raiden.settings import GAS_LIMIT
from raiden.tests.unit.test_channelstate import create_channel_from_models, create_model
from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    HOP1,
    HOP2,
    UNIT_CHANNEL_ID,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    make_block_hash,
)
from raiden.transfer.architecture import SendMessageEvent, TransitionResult
from raiden.transfer.channel import get_status
from raiden.transfer.events import (
    ContractSendChannelBatchUnlock,
    ContractSendChannelUpdateTransfer,
    ContractSendSecretReveal,
)
from raiden.transfer.identifiers import (
    CANONICAL_IDENTIFIER_UNORDERED_QUEUE,
    CanonicalIdentifier,
    QueueIdentifier,
)
from raiden.transfer.mediated_transfer.state import MediatorTransferState, TargetTransferState
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.mediated_transfer.tasks import MediatorTask, TargetTask
from raiden.transfer.node import (
    handle_action_change_node_network_state,
    handle_contract_receive_new_token_network,
    handle_contract_receive_new_token_network_registry,
    handle_receive_delivered,
    handle_receive_processed,
    inplace_delete_message_queue,
    is_transaction_effect_satisfied,
    is_transaction_expired,
    maybe_add_tokennetwork,
    state_transition,
    subdispatch_by_canonical_id,
    subdispatch_initiatortask,
    subdispatch_targettask,
    subdispatch_to_paymenttask,
)
from raiden.transfer.state import (
    BalanceProofSignedState,
    ChannelState,
    HopState,
    NetworkState,
    PendingLocksState,
    RouteState,
    TokenNetworkGraphState,
    TokenNetworkRegistryState,
    TokenNetworkState,
)
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    ActionChannelClose,
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelSettled,
    ContractReceiveNewTokenNetwork,
    ContractReceiveNewTokenNetworkRegistry,
    ReceiveDelivered,
    ReceiveProcessed,
)
from raiden.transfer.views import get_networks
from raiden.utils.copy import deepcopy


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
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        unlocked_amount=0,
        returned_tokens=0,
        block_number=1,
        block_hash=make_block_hash(),
    )
    # unlock for a channel in which this node is not a participant must return False
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    # now call normally with us being the partner and not the participant
    state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=UNIT_SECRETHASH,
        canonical_identifier=canonical_identifier,
        receiver=netting_channel_state.our_state.address,
        sender=netting_channel_state.partner_state.address,
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        unlocked_amount=0,
        returned_tokens=0,
        block_number=1,
        block_hash=make_block_hash(),
    )
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    # finally call with us being the participant and not the partner which should check out
    state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=UNIT_SECRETHASH,
        canonical_identifier=canonical_identifier,
        receiver=netting_channel_state.partner_state.address,
        sender=netting_channel_state.our_state.address,
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        unlocked_amount=0,
        returned_tokens=0,
        block_number=1,
        block_hash=make_block_hash(),
    )

    # ContractSendChannelBatchUnlock would only be satisfied if both sides are unlocked
    # and if the channel was cleared
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    channel_settled = ContractReceiveChannelSettled(
        transaction_hash=bytes(32),
        canonical_identifier=canonical_identifier,
        our_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        block_number=1,
        block_hash=make_block_hash(),
    )

    iteration = state_transition(chain_state=chain_state, state_change=channel_settled)

    assert is_transaction_effect_satisfied(iteration.new_state, transaction, state_change)


def test_subdispatch_invalid_initiatortask(chain_state, token_network_address):
    subtask = object()
    chain_state.payment_mapping.secrethashes_to_task[UNIT_SECRETHASH] = subtask
    transition_result = subdispatch_initiatortask(
        chain_state=chain_state,
        state_change=None,
        token_network_address=token_network_address,
        secrethash=UNIT_SECRETHASH,
    )
    assert transition_result.new_state == chain_state
    assert not transition_result.events


def test_subdispatch_invalid_targettask(chain_state, token_network_address):
    subtask = object()
    chain_state.payment_mapping.secrethashes_to_task[UNIT_SECRETHASH] = subtask
    transition_result = subdispatch_targettask(
        chain_state=chain_state,
        state_change=None,
        token_network_address=token_network_address,
        channel_identifier=UNIT_CHANNEL_ID,
        secrethash=UNIT_SECRETHASH,
    )
    assert transition_result.new_state == chain_state
    assert not transition_result.events


@pytest.mark.parametrize("partner", [factories.UNIT_TRANSFER_SENDER])
def test_subdispatch_to_paymenttask_target(chain_state, netting_channel_state):
    target_state = TargetTransferState(
        from_hop=HopState(
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
    netting_channel_state.partner_state.pending_locks = PendingLocksState([bytes(lock.encoded)])
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
            locksroot=LOCKSROOT_OF_NO_LOCKS,
        )
    )
    state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        sender=netting_channel_state.partner_state.address,
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


def test_maybe_add_tokennetwork_unknown_token_network_registry(chain_state, token_network_address):
    token_network_registry_address = factories.make_address()
    token_address = factories.make_address()
    token_network = TokenNetworkState(
        address=token_network_address,
        token_address=token_address,
        network_graph=TokenNetworkGraphState(token_network_address=token_network_address),
    )
    msg = "test state invalid, token_network_registry already in chain_state"
    assert (
        token_network_registry_address not in chain_state.identifiers_to_tokennetworkregistries
    ), msg
    maybe_add_tokennetwork(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_network_state=token_network,
    )
    # new token network registry should have been added to chain_state
    token_network_registry_state = chain_state.identifiers_to_tokennetworkregistries[
        token_network_registry_address
    ]
    assert token_network_registry_state.address == token_network_registry_address


def test_handle_new_token_network(chain_state, token_network_address):
    token_address = factories.make_address()
    token_network = TokenNetworkState(
        address=token_network_address,
        token_address=token_address,
        network_graph=TokenNetworkGraphState(token_network_address=token_network_address),
    )
    token_network_registry_address = factories.make_address()
    state_change = ContractReceiveNewTokenNetwork(
        token_network_registry_address=token_network_registry_address,
        token_network=token_network,
        transaction_hash=factories.make_transaction_hash(),
        block_hash=factories.make_block_hash(),
        block_number=factories.make_block_number(),
    )
    transition_result = handle_contract_receive_new_token_network(
        chain_state=chain_state, state_change=state_change
    )
    new_chain_state = transition_result.new_state
    token_network_registry = new_chain_state.identifiers_to_tokennetworkregistries[
        token_network_registry_address
    ]
    assert token_network_registry.address == token_network_registry_address
    assert not transition_result.events
    assert get_networks(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    ) == (token_network_registry, token_network)


def test_is_transaction_expired():
    expiration = 24
    block_number = expiration + 1
    transaction = ContractSendChannelUpdateTransfer(
        expiration=expiration,
        balance_proof=None,
        triggered_by_block_hash=factories.make_block_hash(),
    )
    assert is_transaction_expired(transaction, block_number)
    transaction = ContractSendSecretReveal(
        expiration=expiration,
        secret=factories.UNIT_SECRET,
        triggered_by_block_hash=factories.make_block_hash(),
    )
    assert is_transaction_expired(transaction, block_number)

    transaction = ContractSendSecretReveal(
        expiration=block_number,
        secret=factories.UNIT_SECRET,
        triggered_by_block_hash=factories.make_block_hash(),
    )
    assert not is_transaction_expired(transaction, block_number)


def test_subdispatch_by_canonical_id(chain_state):
    our_model, _ = create_model(balance=10, num_pending_locks=1)
    partner_model, _ = create_model(balance=0, num_pending_locks=0)
    channel_state = create_channel_from_models(
        our_model, partner_model, factories.make_privatekey_bin()
    )
    canonical_identifier = channel_state.canonical_identifier
    token_network = TokenNetworkState(
        address=canonical_identifier.token_network_address,
        token_address=factories.make_address(),
        network_graph=TokenNetworkGraphState(
            token_network_address=channel_state.token_network_address
        ),
    )
    token_network.partneraddresses_to_channelidentifiers[
        partner_model.participant_address
    ] = canonical_identifier.channel_identifier
    token_network.channelidentifiers_to_channels[
        canonical_identifier.channel_identifier
    ] = channel_state
    token_network_registry = TokenNetworkRegistryState(
        address=factories.make_address(), token_network_list=[token_network]
    )
    chain_state.identifiers_to_tokennetworkregistries[
        token_network_registry.address
    ] = token_network_registry
    chain_state.tokennetworkaddresses_to_tokennetworkregistryaddresses[
        canonical_identifier.token_network_address
    ] = token_network_registry.address
    # dispatching a Block will be ignored
    previous_state = deepcopy(chain_state)
    state_change = Block(
        block_number=chain_state.block_number,
        gas_limit=GAS_LIMIT,
        block_hash=chain_state.block_hash,
    )
    transition_result = subdispatch_by_canonical_id(
        chain_state=chain_state,
        canonical_identifier=canonical_identifier,
        state_change=state_change,
    )
    assert transition_result.new_state == previous_state
    assert transition_result.events == []

    state_change = ActionChannelClose(canonical_identifier=canonical_identifier)

    # dispatching for an unknown canonical_identifier will not emit events
    transition_result = subdispatch_by_canonical_id(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=factories.make_address(),
            channel_identifier=factories.make_channel_identifier(),
        ),
        state_change=state_change,
    )
    assert not transition_result.events, transition_result

    assert get_status(channel_state) == ChannelState.STATE_OPENED
    transition_result = subdispatch_by_canonical_id(
        chain_state=chain_state,
        canonical_identifier=canonical_identifier,
        state_change=state_change,
    )

    assert get_status(channel_state) == ChannelState.STATE_CLOSING
    assert transition_result.new_state == chain_state, transition_result


def test_handle_node_change_network_state(chain_state, netting_channel_state, monkeypatch):
    state_change = ActionChangeNodeNetworkState(
        node_address=factories.make_address(), network_state=NetworkState.REACHABLE
    )
    transition_result = handle_action_change_node_network_state(chain_state, state_change)
    # no events if no mediator tasks are there to apply to
    assert not transition_result.events

    mediator_state = MediatorTransferState(
        secrethash=UNIT_SECRETHASH,
        routes=[
            RouteState(
                route=[netting_channel_state.partner_state.address],
                forward_channel_id=netting_channel_state.canonical_identifier.channel_identifier,
            )
        ],
    )
    subtask = MediatorTask(
        token_network_address=netting_channel_state.canonical_identifier.token_network_address,
        mediator_state=mediator_state,
    )
    chain_state.payment_mapping.secrethashes_to_task[UNIT_SECRETHASH] = subtask

    lock = factories.HashTimeLockState(amount=0, expiration=2, secrethash=UNIT_SECRETHASH)

    netting_channel_state.partner_state.secrethashes_to_lockedlocks[UNIT_SECRETHASH] = lock
    netting_channel_state.partner_state.pending_locks = PendingLocksState([bytes(lock.encoded)])
    result = object()
    monkeypatch.setattr(
        raiden.transfer.node,
        "subdispatch_mediatortask",
        lambda *args, **kwargs: TransitionResult(chain_state, [result]),
    )
    transition_result = handle_action_change_node_network_state(chain_state, state_change)

    assert transition_result.events == [result]


def test_handle_new_token_network_registry(chain_state, token_network_address):
    token_address = factories.make_address()
    token_network = TokenNetworkState(
        address=token_network_address,
        token_address=token_address,
        network_graph=TokenNetworkGraphState(token_network_address=token_network_address),
    )
    token_network_registry = TokenNetworkRegistryState(
        address=factories.make_address(), token_network_list=[token_network]
    )
    state_change = ContractReceiveNewTokenNetworkRegistry(
        transaction_hash=factories.make_transaction_hash(),
        token_network_registry=token_network_registry,
        block_hash=make_block_hash(),
        block_number=1,
    )
    assert token_network_registry.address not in chain_state.identifiers_to_tokennetworkregistries
    transition_result = handle_contract_receive_new_token_network_registry(
        chain_state, state_change
    )
    assert transition_result.new_state == chain_state
    msg = "handle_new_token_network_registry did not add to chain_state mapping"
    assert token_network_registry.address in chain_state.identifiers_to_tokennetworkregistries, msg


def test_inplace_delete_message_queue(chain_state):
    sender = factories.make_address()
    canonical_identifier = factories.make_canonical_identifier()
    message_id = factories.make_message_identifier()
    delivered_state_change = ReceiveDelivered(sender=sender, message_identifier=message_id)
    processed_state_change = ReceiveProcessed(sender=sender, message_identifier=message_id)

    global_identifier = QueueIdentifier(
        recipient=sender, canonical_identifier=CANONICAL_IDENTIFIER_UNORDERED_QUEUE
    )

    chain_state.queueids_to_queues[global_identifier] = None
    assert global_identifier in chain_state.queueids_to_queues, "queue mapping insertion failed"
    inplace_delete_message_queue(
        chain_state=chain_state, state_change=delivered_state_change, queueid=global_identifier
    )
    assert global_identifier not in chain_state.queueids_to_queues, "did not clear queue"

    chain_state.queueids_to_queues[global_identifier] = [
        SendMessageEvent(
            recipient=sender,
            canonical_identifier=canonical_identifier,
            message_identifier=message_id,
        )
    ]
    assert global_identifier in chain_state.queueids_to_queues, "queue mapping insertion failed"
    handle_receive_delivered(chain_state=chain_state, state_change=delivered_state_change)
    assert global_identifier not in chain_state.queueids_to_queues, "did not clear queue"

    queue_identifier = QueueIdentifier(recipient=sender, canonical_identifier=canonical_identifier)
    assert queue_identifier not in chain_state.queueids_to_queues, "queue not empty"
    chain_state.queueids_to_queues[queue_identifier] = [
        SendMessageEvent(
            recipient=sender,
            canonical_identifier=canonical_identifier,
            message_identifier=message_id,
        )
    ]
    assert queue_identifier in chain_state.queueids_to_queues, "queue mapping not mutable"
    handle_receive_processed(chain_state=chain_state, state_change=processed_state_change)
    assert queue_identifier not in chain_state.queueids_to_queues, "queue did not clear"
