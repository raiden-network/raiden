import random
from hashlib import sha256

import pytest
from eth_utils import keccak

from raiden.constants import LOCKSROOT_OF_NO_LOCKS
from raiden.routing import get_best_routes
from raiden.settings import INTERNAL_ROUTING_DEFAULT_FEE_PERC
from raiden.tests.utils import factories
from raiden.tests.utils.transfer import make_receive_transfer_mediated
from raiden.transfer import node, token_network, views
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.transfer.state import (
    HashTimeLockState,
    NetworkState,
    PendingLocksState,
    RouteState,
    TokenNetworkGraphState,
    TokenNetworkState,
)
from raiden.transfer.state_change import (
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
)
from raiden.utils.copy import deepcopy


@pytest.fixture
def channel_properties(our_address, token_network_state):
    partner_privkey, address = factories.make_privkey_address()
    properties = factories.NettingChannelStateProperties(
        our_state=factories.NettingChannelEndStateProperties(balance=80, address=our_address),
        partner_state=factories.NettingChannelEndStateProperties(balance=80, address=address),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address
        ),
    )
    return properties, partner_privkey


def test_contract_receive_channelnew_must_be_idempotent(channel_properties):
    block_number = 10
    block_hash = factories.make_block_hash()

    token_network_address = factories.make_address()
    token_id = factories.make_address()
    token_network_state = TokenNetworkState(
        address=token_network_address,
        token_address=token_id,
        network_graph=TokenNetworkGraphState(token_network_address),
    )

    pseudo_random_generator = random.Random()

    properties, _ = channel_properties
    channel_state1 = factories.create(properties)
    channel_state2 = deepcopy(channel_state1)

    state_change1 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state1,
        block_number=block_number,
        block_hash=block_hash,
    )

    token_network.state_transition(
        token_network_state=token_network_state,
        state_change=state_change1,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    state_change2 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state2,
        block_number=block_number + 1,
        block_hash=factories.make_block_hash(),
    )

    # replay the ContractReceiveChannelNew state change
    iteration = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=state_change2,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    msg = "the channel must not have been overwritten"
    channelmap_by_id = iteration.new_state.channelidentifiers_to_channels
    assert channelmap_by_id[channel_state1.identifier] == channel_state1, msg

    channelmap_by_address = iteration.new_state.partneraddresses_to_channelidentifiers
    partner_channels_ids = channelmap_by_address[channel_state1.partner_state.address]
    assert channel_state1.identifier in partner_channels_ids, msg


def test_channel_settle_must_properly_cleanup(channel_properties):
    open_block_number = 10
    open_block_hash = factories.make_block_hash()

    pseudo_random_generator = random.Random()

    token_network_address = factories.make_address()
    token_id = factories.make_address()
    token_network_state = TokenNetworkState(
        address=token_network_address,
        token_address=token_id,
        network_graph=TokenNetworkGraphState(token_network_address),
    )

    properties, _ = channel_properties
    channel_state = factories.create(properties)

    channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change,
        block_number=open_block_number,
        block_hash=open_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    closed_block_number = open_block_number + 10
    closed_block_hash = factories.make_block_hash()
    channel_close_state_change = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.partner_state.address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )

    channel_closed_iteration = token_network.state_transition(
        token_network_state=channel_new_iteration.new_state,
        state_change=channel_close_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        block_number=settle_block_number,
        block_hash=factories.make_block_hash(),
        our_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
    )

    channel_settled_iteration = token_network.state_transition(
        token_network_state=channel_closed_iteration.new_state,
        state_change=channel_settled_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert channel_state.identifier in ids_to_channels


def test_channel_data_removed_after_unlock(
    chain_state, token_network_state, our_address, channel_properties
):
    open_block_number = 10
    open_block_hash = factories.make_block_hash()

    pseudo_random_generator = random.Random()

    properties, pkey = channel_properties
    address = properties.partner_state.address
    channel_state = factories.create(properties)

    channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change,
        block_number=open_block_number,
        block_hash=open_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    lock_amount = 30
    lock_expiration = 20
    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    mediated_transfer = make_receive_transfer_mediated(
        channel_state=channel_state, privkey=pkey, nonce=1, transferred_amount=0, lock=lock
    )

    from_hop = factories.make_hop_from_channel(channel_state)
    init_target = ActionInitTarget(
        sender=mediated_transfer.balance_proof.sender,  # pylint: disable=no-member
        balance_proof=mediated_transfer.balance_proof,
        from_hop=from_hop,
        transfer=mediated_transfer,
    )

    node.state_transition(chain_state, init_target)

    closed_block_number = open_block_number + 10
    closed_block_hash = factories.make_block_hash()
    channel_close_state_change = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.partner_state.address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )

    channel_closed_iteration = token_network.state_transition(
        token_network_state=channel_new_iteration.new_state,
        state_change=channel_close_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )
    channel_state_after_closed = channel_closed_iteration.new_state.channelidentifiers_to_channels[
        channel_state.identifier
    ]

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        block_number=settle_block_number,
        block_hash=factories.make_block_hash(),
        our_onchain_locksroot=compute_locksroot(
            channel_state_after_closed.our_state.pending_locks
        ),
        partner_onchain_locksroot=compute_locksroot(
            channel_state_after_closed.partner_state.pending_locks
        ),
    )

    channel_settled_iteration = token_network.state_transition(
        token_network_state=channel_closed_iteration.new_state,
        state_change=channel_settled_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert len(ids_to_channels) == 1
    assert channel_state.identifier in ids_to_channels

    unlock_blocknumber = settle_block_number + 5
    channel_batch_unlock_state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        receiver=our_address,
        sender=address,
        locksroot=compute_locksroot(PendingLocksState([bytes(lock.encoded)])),
        unlocked_amount=lock_amount,
        returned_tokens=0,
        block_number=closed_block_number + 1,
        block_hash=factories.make_block_hash(),
    )
    channel_unlock_iteration = token_network.state_transition(
        token_network_state=channel_settled_iteration.new_state,
        state_change=channel_batch_unlock_state_change,
        block_number=unlock_blocknumber,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    token_network_state_after_unlock = channel_unlock_iteration.new_state
    ids_to_channels = token_network_state_after_unlock.channelidentifiers_to_channels
    assert len(ids_to_channels) == 1


@pytest.mark.skip("Raiddit")
def test_mediator_clear_pairs_after_batch_unlock(
    chain_state, token_network_state, our_address, channel_properties
):
    """ Regression test for https://github.com/raiden-network/raiden/issues/2932
    The mediator must also clear the transfer pairs once a ReceiveBatchUnlock where
    he is a participant is received.
    """
    open_block_number = 10
    open_block_hash = factories.make_block_hash()

    pseudo_random_generator = random.Random()

    properties, pkey = channel_properties
    address = properties.partner_state.address
    channel_state = factories.create(properties)

    channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change,
        block_number=open_block_number,
        block_hash=open_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    lock_amount = 30
    lock_expiration = 20
    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    mediated_transfer = make_receive_transfer_mediated(
        channel_state=channel_state, privkey=pkey, nonce=1, transferred_amount=0, lock=lock
    )

    route_state = RouteState(
        route=[channel_state.our_state.address, channel_state.partner_state.address],
        forward_channel_id=channel_state.canonical_identifier.channel_identifier,
    )
    from_hop = factories.make_hop_from_channel(channel_state)
    init_mediator = ActionInitMediator(
        route_states=[route_state],
        from_hop=from_hop,
        from_transfer=mediated_transfer,
        balance_proof=mediated_transfer.balance_proof,
        sender=mediated_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    node.state_transition(chain_state, init_mediator)

    closed_block_number = open_block_number + 10
    closed_block_hash = factories.make_block_hash()
    channel_close_state_change = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.partner_state.address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )

    channel_closed_iteration = token_network.state_transition(
        token_network_state=channel_new_iteration.new_state,
        state_change=channel_close_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        block_number=settle_block_number,
        block_hash=factories.make_block_hash(),
        our_onchain_locksroot=factories.make_32bytes(),
        partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
    )

    channel_settled_iteration = token_network.state_transition(
        token_network_state=channel_closed_iteration.new_state,
        state_change=channel_settled_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert len(ids_to_channels) == 1
    assert channel_state.identifier in ids_to_channels

    block_number = closed_block_number + 1
    channel_batch_unlock_state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        receiver=address,
        sender=our_address,
        locksroot=compute_locksroot(PendingLocksState([bytes(lock.encoded)])),
        unlocked_amount=lock_amount,
        returned_tokens=0,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
    )
    channel_unlock_iteration = node.state_transition(
        chain_state=chain_state, state_change=channel_batch_unlock_state_change
    )
    chain_state = channel_unlock_iteration.new_state
    token_network_state = views.get_token_network_by_address(
        chain_state=chain_state, token_network_address=token_network_state.address
    )
    ids_to_channels = token_network_state.channelidentifiers_to_channels
    assert len(ids_to_channels) == 0

    # Make sure that all is fine in the next block
    block = Block(
        block_number=block_number + 1, gas_limit=1, block_hash=factories.make_transaction_hash()
    )
    iteration = node.state_transition(chain_state=chain_state, state_change=block)
    assert iteration.new_state

    # Make sure that mediator task was cleared during the next block processing
    # since the channel was removed
    mediator_task = chain_state.payment_mapping.secrethashes_to_task.get(lock_secrethash)
    assert not mediator_task


def test_multiple_channel_states(chain_state, token_network_state, channel_properties):
    open_block_number = 10
    open_block_hash = factories.make_block_hash()

    pseudo_random_generator = random.Random()

    properties, pkey = channel_properties
    channel_state = factories.create(properties)

    channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change,
        block_number=open_block_number,
        block_hash=open_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    lock_amount = 30
    lock_expiration = 20
    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()
    lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

    mediated_transfer = make_receive_transfer_mediated(
        channel_state=channel_state, privkey=pkey, nonce=1, transferred_amount=0, lock=lock
    )

    from_hop = factories.make_hop_from_channel(channel_state)
    init_target = ActionInitTarget(
        from_hop=from_hop,
        transfer=mediated_transfer,
        balance_proof=mediated_transfer.balance_proof,
        sender=mediated_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    node.state_transition(chain_state, init_target)

    closed_block_number = open_block_number + 10
    closed_block_hash = factories.make_block_hash()
    channel_close_state_change = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.partner_state.address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )

    channel_closed_iteration = token_network.state_transition(
        token_network_state=channel_new_iteration.new_state,
        state_change=channel_close_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=channel_state.canonical_identifier,
        block_number=settle_block_number,
        block_hash=factories.make_block_hash(),
        our_onchain_locksroot=factories.make_32bytes(),
        partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
    )

    channel_settled_iteration = token_network.state_transition(
        token_network_state=channel_closed_iteration.new_state,
        state_change=channel_settled_state_change,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert len(ids_to_channels) == 1
    assert channel_state.identifier in ids_to_channels

    # Create new channel while the previous one is pending unlock
    new_channel_properties = factories.create_properties(
        factories.NettingChannelStateProperties(
            canonical_identifier=factories.make_canonical_identifier()
        ),
        defaults=properties,
    )
    new_channel_state = factories.create(new_channel_properties)

    channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=new_channel_state,
        block_number=closed_block_number + 1,
        block_hash=factories.make_block_hash(),
    )

    channel_new_iteration = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change,
        block_number=open_block_number,
        block_hash=open_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    token_network_state_after_new_open = channel_new_iteration.new_state
    ids_to_channels = token_network_state_after_new_open.channelidentifiers_to_channels

    assert len(ids_to_channels) == 2
    assert channel_state.identifier in ids_to_channels


def test_routing_updates(token_network_state, our_address, channel_properties):
    open_block_number = 10
    properties, _ = channel_properties
    address1 = properties.partner_state.address
    address2 = factories.make_address()
    address3 = factories.make_address()
    pseudo_random_generator = random.Random()

    channel_state = factories.create(properties)

    open_block_hash = factories.make_block_hash()
    # create a new channel as participant, check graph update
    channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration1 = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change,
        block_number=open_block_number,
        block_hash=open_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_new_iteration1.new_state.network_graph
    assert channel_state.identifier in graph_state.channel_identifier_to_participants
    assert len(graph_state.channel_identifier_to_participants) == 1
    assert graph_state.network[our_address][address1] is not None
    assert len(graph_state.network.edges()) == 1

    # create a new channel without being participant, check graph update
    new_channel_identifier = factories.make_channel_identifier()
    channel_new_state_change = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address,
            channel_identifier=new_channel_identifier,
        ),
        participant1=address2,
        participant2=address3,
        block_number=open_block_number,
        block_hash=open_block_hash,
    )

    channel_new_iteration2 = token_network.state_transition(
        token_network_state=channel_new_iteration1.new_state,
        state_change=channel_new_state_change,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_new_iteration2.new_state.network_graph
    assert channel_state.identifier in graph_state.channel_identifier_to_participants
    assert new_channel_identifier in graph_state.channel_identifier_to_participants
    assert len(graph_state.channel_identifier_to_participants) == 2
    assert graph_state.network[our_address][address1] is not None
    assert graph_state.network[address2][address3] is not None
    assert len(graph_state.network.edges()) == 2

    # close the channel the node is a participant of, check edge is removed from graph
    closed_block_number = open_block_number + 20
    closed_block_hash = factories.make_block_hash()
    channel_close_state_change1 = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.partner_state.address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )

    channel_closed_iteration1 = token_network.state_transition(
        token_network_state=channel_new_iteration2.new_state,
        state_change=channel_close_state_change1,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    # Check that a second ContractReceiveChannelClosed events is handled properly
    # This might have been sent from the other participant of the channel
    # See issue #2449
    channel_close_state_change2 = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.our_state.address,
        canonical_identifier=channel_state.canonical_identifier,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )

    channel_closed_iteration2 = token_network.state_transition(
        token_network_state=channel_closed_iteration1.new_state,
        state_change=channel_close_state_change2,
        block_number=closed_block_number,
        block_hash=closed_block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_closed_iteration2.new_state.network_graph
    assert channel_state.identifier not in graph_state.channel_identifier_to_participants
    assert new_channel_identifier in graph_state.channel_identifier_to_participants
    assert len(graph_state.channel_identifier_to_participants) == 1
    assert graph_state.network[address2][address3] is not None
    assert len(graph_state.network.edges()) == 1

    # close the channel the node is not a participant of, check edge is removed from graph
    channel_close_state_change3 = ContractReceiveRouteClosed(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address,
            channel_identifier=new_channel_identifier,
        ),
        block_number=closed_block_number,
        block_hash=closed_block_hash,
    )

    channel_closed_iteration3 = token_network.state_transition(
        token_network_state=channel_closed_iteration2.new_state,
        state_change=channel_close_state_change3,
        block_number=closed_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    # Check that a second ContractReceiveRouteClosed events is handled properly.
    # This might have been sent from the second participant of the channel
    # See issue #2449
    closed_block_plus_10_hash = factories.make_block_hash()
    channel_close_state_change4 = ContractReceiveRouteClosed(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address,
            channel_identifier=new_channel_identifier,
        ),
        block_number=closed_block_number + 10,
        block_hash=closed_block_plus_10_hash,
    )

    channel_closed_iteration4 = token_network.state_transition(
        token_network_state=channel_closed_iteration3.new_state,
        state_change=channel_close_state_change4,
        block_number=closed_block_number + 10,
        block_hash=closed_block_plus_10_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_closed_iteration4.new_state.network_graph
    assert channel_state.identifier not in graph_state.channel_identifier_to_participants
    assert new_channel_identifier not in graph_state.channel_identifier_to_participants
    assert len(graph_state.channel_identifier_to_participants) == 0
    assert len(graph_state.network.edges()) == 0


def test_routing_issue2663(chain_state, token_network_state, one_to_n_address, our_address):
    open_block_number = 10
    open_block_number_hash = factories.make_block_hash()
    address1 = factories.make_address()
    address2 = factories.make_address()
    address3 = factories.make_address()
    address4 = factories.make_address()
    pseudo_random_generator = random.Random()

    # Create a network with the following topology
    #
    # our  ----- 50 ---->  (1) <------50------
    #  |                                    |
    #  |                                    |
    # 100                                  (4)
    #  |                                    ^
    #  v                                    |
    # (2)  ----- 100 --->  (3) <-------100---

    channel_state1 = factories.create(
        factories.NettingChannelStateProperties(
            our_state=factories.NettingChannelEndStateProperties(balance=50, address=our_address),
            partner_state=factories.NettingChannelEndStateProperties(balance=0, address=address1),
        )
    )
    channel_state2 = factories.create(
        factories.NettingChannelStateProperties(
            our_state=factories.NettingChannelEndStateProperties(balance=100, address=our_address),
            partner_state=factories.NettingChannelEndStateProperties(balance=0, address=address2),
        )
    )

    # create new channels as participant
    channel_new_state_change1 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state1,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )
    channel_new_state_change2 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state2,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    channel_new_iteration1 = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change1,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    channel_new_iteration2 = token_network.state_transition(
        token_network_state=channel_new_iteration1.new_state,
        state_change=channel_new_state_change2,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_new_iteration2.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 2
    assert len(graph_state.network.edges()) == 2

    # create new channels without being participant
    channel_new_state_change3 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=3
        ),
        participant1=address2,
        participant2=address3,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    channel_new_iteration3 = token_network.state_transition(
        token_network_state=channel_new_iteration2.new_state,
        state_change=channel_new_state_change3,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_new_iteration3.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 3
    assert len(graph_state.network.edges()) == 3

    channel_new_state_change4 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=4
        ),
        participant1=address3,
        participant2=address4,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )
    channel_new_iteration4 = token_network.state_transition(
        token_network_state=channel_new_iteration3.new_state,
        state_change=channel_new_state_change4,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_new_iteration4.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 4
    assert len(graph_state.network.edges()) == 4

    channel_new_state_change5 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=5
        ),
        participant1=address1,
        participant2=address4,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )
    channel_new_iteration5 = token_network.state_transition(
        token_network_state=channel_new_iteration4.new_state,
        state_change=channel_new_state_change5,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = channel_new_iteration5.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 5
    assert len(graph_state.network.edges()) == 5

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
        address4: NetworkState.REACHABLE,
    }

    error_msg, routes1, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address4,
        amount=50,
        previous_address=None,
        pfs_config=None,
        privkey=b"",  # not used if pfs is not configured
    )
    assert routes1, error_msg
    assert routes1[0].next_hop_address == address1, error_msg
    assert routes1[1].next_hop_address == address2, error_msg

    # test routing with node 2 offline
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.UNREACHABLE,
        address3: NetworkState.REACHABLE,
        address4: NetworkState.REACHABLE,
    }

    _, routes1, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address4,
        amount=50,
        previous_address=None,
        pfs_config=None,
        privkey=b"",
    )
    assert routes1[0].next_hop_address == address1

    # test routing with node 3 offline
    # the routing doesn't care as node 3 is not directly connected
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.UNREACHABLE,
        address4: NetworkState.REACHABLE,
    }

    _, routes1, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address4,
        amount=50,
        previous_address=None,
        pfs_config=None,
        privkey=b"",
    )
    assert routes1[0].next_hop_address == address1
    assert routes1[1].next_hop_address == address2

    # test routing with node 1 offline
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.UNREACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
        address4: NetworkState.REACHABLE,
    }

    _, routes1, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address3,
        amount=50,
        previous_address=None,
        pfs_config=None,
        privkey=b"",
    )
    # right now the channel to 1 gets filtered out as it is offline
    assert routes1[0].next_hop_address == address2


def test_routing_priority(chain_state, token_network_state, one_to_n_address, our_address):
    open_block_number = factories.make_block_number()
    open_block_number_hash = factories.make_block_hash()
    address1 = factories.make_address()
    address2 = factories.make_address()
    address3 = factories.make_address()
    address4 = factories.make_address()
    pseudo_random_generator = random.Random()
    # Create a network with the following topology
    #
    # our  ----- 1/1 ----> (1)
    #  |                    |
    #  |                    |
    #  2/0                  x
    #  |                    |
    #  v                    v
    # (2)  ----- x ----->  (3)
    #  |                    |
    #  |                    |
    #  x                    x
    #  |                    |
    #  v                    v
    # (4)                  (4)

    channel_state1 = factories.create(
        factories.NettingChannelStateProperties(
            our_state=factories.NettingChannelEndStateProperties(balance=1, address=our_address),
            partner_state=factories.NettingChannelEndStateProperties(balance=1, address=address1),
        )
    )
    channel_state2 = factories.create(
        factories.NettingChannelStateProperties(
            our_state=factories.NettingChannelEndStateProperties(balance=2, address=our_address),
            partner_state=factories.NettingChannelEndStateProperties(balance=0, address=address2),
        )
    )

    # create new channels as participant
    channel_new_state_change1 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state1,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )
    channel_new_state_change2 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=channel_state2,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    channel_new_iteration1 = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=channel_new_state_change1,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    channel_new_iteration2 = token_network.state_transition(
        token_network_state=channel_new_iteration1.new_state,
        state_change=channel_new_state_change2,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    # create new channels without being participant
    channel_new_state_change3 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=3
        ),
        participant1=address2,
        participant2=address3,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    channel_new_iteration3 = token_network.state_transition(
        token_network_state=channel_new_iteration2.new_state,
        state_change=channel_new_state_change3,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    channel_new_state_change4 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=4
        ),
        participant1=address3,
        participant2=address1,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    channel_new_iteration4 = token_network.state_transition(
        token_network_state=channel_new_iteration3.new_state,
        state_change=channel_new_state_change4,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    channel_new_state_change5 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=4
        ),
        participant1=address3,
        participant2=address4,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    channel_new_iteration5 = token_network.state_transition(
        token_network_state=channel_new_iteration4.new_state,
        state_change=channel_new_state_change5,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    channel_new_state_change6 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=4
        ),
        participant1=address2,
        participant2=address4,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    token_network.state_transition(
        token_network_state=channel_new_iteration5.new_state,
        state_change=channel_new_state_change6,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    # test routing priority with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
    }

    error_msg, routes, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address3,
        amount=1,
        previous_address=None,
        pfs_config=None,
        privkey=b"",
    )
    assert routes, error_msg
    assert routes[0].next_hop_address == address1, error_msg
    assert routes[1].next_hop_address == address2, error_msg

    # number of hops overwrites refunding capacity (route over node 2 involves less hops)
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
        address3: NetworkState.REACHABLE,
        address4: NetworkState.REACHABLE,
    }

    _, routes, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address4,
        amount=1,
        previous_address=None,
        pfs_config=None,
        privkey=b"",
    )
    assert routes[0].next_hop_address == address2
    assert routes[1].next_hop_address == address1


def test_internal_routing_mediation_fees(
    chain_state, token_network_state, one_to_n_address, our_address
):
    """
    Checks that requesting a route for a single-hop transfer
    will return the route with estimated_fee of zero.
    """
    open_block_number = 10
    open_block_number_hash = factories.make_block_hash()
    address1 = factories.make_address()
    address2 = factories.make_address()
    pseudo_random_generator = random.Random()

    direct_channel_state = factories.create(
        factories.NettingChannelStateProperties(
            our_state=factories.NettingChannelEndStateProperties(balance=50, address=our_address),
            partner_state=factories.NettingChannelEndStateProperties(balance=0, address=address1),
        )
    )

    # create new channels as participant
    direct_channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        channel_state=direct_channel_state,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    direct_channel_new_iteration = token_network.state_transition(
        token_network_state=token_network_state,
        state_change=direct_channel_new_state_change,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
        pseudo_random_generator=pseudo_random_generator,
    )

    route_new_state_change = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        canonical_identifier=factories.make_canonical_identifier(
            token_network_address=token_network_state.address, channel_identifier=4
        ),
        participant1=address1,
        participant2=address2,
        block_number=open_block_number,
        block_hash=open_block_number_hash,
    )

    route_new_iteration = token_network.state_transition(
        token_network_state=direct_channel_new_iteration.new_state,
        state_change=route_new_state_change,
        block_number=open_block_number + 10,
        block_hash=factories.make_block_hash(),
        pseudo_random_generator=pseudo_random_generator,
    )

    graph_state = route_new_iteration.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 2
    assert len(graph_state.network.edges()) == 2

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NetworkState.REACHABLE,
        address2: NetworkState.REACHABLE,
    }

    # Routing to our direct partner would require 0 mediation fees.x
    _, routes, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address1,
        amount=50,
        previous_address=None,
        pfs_config=None,
        privkey=b"",  # not used if pfs is not configured
    )
    assert routes[0].estimated_fee == 0

    # Routing to our address2 through address1 would charge 2%
    error_msg, routes, _ = get_best_routes(
        chain_state=chain_state,
        token_network_address=token_network_state.address,
        one_to_n_address=one_to_n_address,
        from_address=our_address,
        to_address=address2,
        amount=50,
        previous_address=None,
        pfs_config=None,
        privkey=b"",  # not used if pfs is not configured
    )
    assert routes, error_msg
    assert routes[0].estimated_fee == round(INTERNAL_ROUTING_DEFAULT_FEE_PERC * 50), error_msg
