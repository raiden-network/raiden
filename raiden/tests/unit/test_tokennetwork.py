import copy
import random

from raiden.constants import UINT64_MAX
from raiden.routing import get_best_routes
from raiden.tests.utils import factories
from raiden.tests.utils.transfer import make_receive_transfer_mediated
from raiden.transfer import channel, node, token_network, views
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNREACHABLE,
    HashTimeLockState,
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
from raiden.utils import sha3


def test_contract_receive_channelnew_must_be_idempotent():
    block_number = 10
    pseudo_random_generator = random.Random()

    token_network_id = factories.make_address()
    token_id = factories.make_address()
    token_network_state = TokenNetworkState(token_network_id, token_id)
    payment_network_identifier = factories.make_payment_network_identifier()

    amount = 30
    our_balance = amount + 50
    channel_state1 = factories.make_channel(our_balance=our_balance)
    channel_state2 = copy.deepcopy(channel_state1)

    state_change1 = ContractReceiveChannelNew(
        factories.make_transaction_hash(),
        token_network_id,
        channel_state1,
        block_number,
    )

    token_network.state_transition(
        payment_network_identifier,
        token_network_state,
        state_change1,
        pseudo_random_generator,
        block_number,
    )

    # change the existing channel
    payment_identifier = 1
    message_identifier = random.randint(0, UINT64_MAX)
    channel.send_directtransfer(
        channel_state1,
        amount,
        message_identifier,
        payment_identifier,
    )

    state_change2 = ContractReceiveChannelNew(
        factories.make_transaction_hash(),
        token_network_id,
        channel_state2,
        block_number + 1,
    )

    # replay the ContractReceiveChannelNew state change
    iteration = token_network.state_transition(
        payment_network_identifier,
        token_network_state,
        state_change2,
        pseudo_random_generator,
        block_number,
    )

    msg = 'the channel must not been overwritten'
    channelmap_by_id = iteration.new_state.channelidentifiers_to_channels
    assert channelmap_by_id[channel_state1.identifier] == channel_state1, msg

    channelmap_by_address = iteration.new_state.partneraddresses_to_channelidentifiers
    partner_channels_ids = channelmap_by_address[channel_state1.partner_state.address]
    assert channel_state1.identifier in partner_channels_ids, msg


def test_channel_settle_must_properly_cleanup():
    open_block_number = 10
    pseudo_random_generator = random.Random()

    token_network_id = factories.make_address()
    token_id = factories.make_address()
    token_network_state = TokenNetworkState(token_network_id, token_id)
    payment_network_identifier = factories.make_payment_network_identifier()

    amount = 30
    our_balance = amount + 50
    channel_state = factories.make_channel(our_balance=our_balance)

    channel_new_state_change = ContractReceiveChannelNew(
        factories.make_transaction_hash(),
        token_network_id,
        channel_state,
        open_block_number,
    )

    channel_new_iteration = token_network.state_transition(
        payment_network_identifier,
        token_network_state,
        channel_new_state_change,
        pseudo_random_generator,
        open_block_number,
    )

    closed_block_number = open_block_number + 10
    channel_close_state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        channel_state.partner_state.address,
        token_network_id,
        channel_state.identifier,
        closed_block_number,
    )

    channel_closed_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_new_iteration.new_state,
        channel_close_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        factories.make_transaction_hash(),
        token_network_id,
        channel_state.identifier,
        settle_block_number,
    )

    channel_settled_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_closed_iteration.new_state,
        channel_settled_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert channel_state.identifier not in ids_to_channels


def test_channel_data_removed_after_unlock(
        chain_state,
        token_network_state,
        our_address,
):
    open_block_number = 10
    pseudo_random_generator = random.Random()
    pkey, address = factories.make_privkey_address()

    amount = 30
    our_balance = amount + 50
    channel_state = factories.make_channel(
        our_balance=our_balance,
        our_address=our_address,
        partner_balance=our_balance,
        partner_address=address,
        token_network_identifier=token_network_state.address,
    )
    payment_network_identifier = factories.make_payment_network_identifier()

    channel_new_state_change = ContractReceiveChannelNew(
        factories.make_transaction_hash(),
        token_network_state.address,
        channel_state,
        open_block_number,
    )

    channel_new_iteration = token_network.state_transition(
        payment_network_identifier,
        token_network_state,
        channel_new_state_change,
        pseudo_random_generator,
        open_block_number,
    )

    lock_amount = 30
    lock_expiration = 20
    lock_secret = sha3(b'test_end_state')
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    mediated_transfer = make_receive_transfer_mediated(
        channel_state=channel_state,
        privkey=pkey,
        nonce=1,
        transferred_amount=0,
        lock=lock,
    )

    from_route = factories.route_from_channel(channel_state)
    init_target = ActionInitTarget(
        from_route,
        mediated_transfer,
    )

    node.state_transition(chain_state, init_target)

    closed_block_number = open_block_number + 10
    channel_close_state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        channel_state.partner_state.address,
        token_network_state.address,
        channel_state.identifier,
        closed_block_number,
    )

    channel_closed_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_new_iteration.new_state,
        channel_close_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        factories.make_transaction_hash(),
        token_network_state.address,
        channel_state.identifier,
        settle_block_number,
    )

    channel_settled_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_closed_iteration.new_state,
        channel_settled_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert len(ids_to_channels) == 1
    assert channel_state.identifier in ids_to_channels

    unlock_blocknumber = settle_block_number + 5
    channel_batch_unlock_state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        participant=our_address,
        partner=address,
        locksroot=lock_secrethash,
        unlocked_amount=lock_amount,
        returned_tokens=0,
        block_number=closed_block_number + 1,
    )
    channel_unlock_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_settled_iteration.new_state,
        channel_batch_unlock_state_change,
        pseudo_random_generator,
        unlock_blocknumber,
    )

    token_network_state_after_unlock = channel_unlock_iteration.new_state
    ids_to_channels = token_network_state_after_unlock.channelidentifiers_to_channels
    assert len(ids_to_channels) == 0


def test_mediator_clear_pairs_after_batch_unlock(
        chain_state,
        token_network_state,
        our_address,
):
    """ Regression test for https://github.com/raiden-network/raiden/issues/2932
    The mediator must also clear the transfer pairs once a ReceiveBatchUnlock where
    he is a participant is received.
    """
    open_block_number = 10
    pseudo_random_generator = random.Random()
    pkey, address = factories.make_privkey_address()

    amount = 30
    our_balance = amount + 50
    channel_state = factories.make_channel(
        our_balance=our_balance,
        our_address=our_address,
        partner_balance=our_balance,
        partner_address=address,
        token_network_identifier=token_network_state.address,
    )
    payment_network_identifier = factories.make_payment_network_identifier()

    channel_new_state_change = ContractReceiveChannelNew(
        factories.make_transaction_hash(),
        token_network_state.address,
        channel_state,
        open_block_number,
    )

    channel_new_iteration = token_network.state_transition(
        payment_network_identifier,
        token_network_state,
        channel_new_state_change,
        pseudo_random_generator,
        open_block_number,
    )

    lock_amount = 30
    lock_expiration = 20
    lock_secret = sha3(b'test_end_state')
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    mediated_transfer = make_receive_transfer_mediated(
        channel_state=channel_state,
        privkey=pkey,
        nonce=1,
        transferred_amount=0,
        lock=lock,
    )

    from_route = factories.route_from_channel(channel_state)
    init_mediator = ActionInitMediator(
        routes=[from_route],
        from_route=from_route,
        from_transfer=mediated_transfer,
    )

    node.state_transition(chain_state, init_mediator)

    closed_block_number = open_block_number + 10
    channel_close_state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        channel_state.partner_state.address,
        token_network_state.address,
        channel_state.identifier,
        closed_block_number,
    )

    channel_closed_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_new_iteration.new_state,
        channel_close_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        factories.make_transaction_hash(),
        token_network_state.address,
        channel_state.identifier,
        settle_block_number,
    )

    channel_settled_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_closed_iteration.new_state,
        channel_settled_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert len(ids_to_channels) == 1
    assert channel_state.identifier in ids_to_channels

    block_number = closed_block_number + 1
    channel_batch_unlock_state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        participant=our_address,
        partner=address,
        locksroot=lock_secrethash,
        unlocked_amount=lock_amount,
        returned_tokens=0,
        block_number=block_number,
    )
    channel_unlock_iteration = node.state_transition(
        chain_state=chain_state,
        state_change=channel_batch_unlock_state_change,
    )
    chain_state = channel_unlock_iteration.new_state
    token_network_state = views.get_token_network_by_identifier(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
    )
    ids_to_channels = token_network_state.channelidentifiers_to_channels
    assert len(ids_to_channels) == 0

    # Make sure that all is fine in the next block
    block = Block(
        block_number=block_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = node.state_transition(
        chain_state=chain_state,
        state_change=block,
    )
    assert iteration.new_state

    # Make sure that mediator task was cleared during the next block processing
    # since the channel was removed
    mediator_task = chain_state.payment_mapping.secrethashes_to_task.get(lock_secrethash)
    assert not mediator_task


def test_multiple_channel_states(
        chain_state,
        token_network_state,
        our_address,
):
    open_block_number = 10
    pseudo_random_generator = random.Random()
    pkey, address = factories.make_privkey_address()

    amount = 30
    our_balance = amount + 50
    channel_state = factories.make_channel(
        our_balance=our_balance,
        our_address=our_address,
        partner_balance=our_balance,
        partner_address=address,
        token_network_identifier=token_network_state.address,
    )
    payment_network_identifier = factories.make_payment_network_identifier()

    channel_new_state_change = ContractReceiveChannelNew(
        factories.make_transaction_hash(),
        token_network_state.address,
        channel_state,
        open_block_number,
    )

    channel_new_iteration = token_network.state_transition(
        payment_network_identifier,
        token_network_state,
        channel_new_state_change,
        pseudo_random_generator,
        open_block_number,
    )

    lock_amount = 30
    lock_expiration = 20
    lock_secret = sha3(b'test_end_state')
    lock_secrethash = sha3(lock_secret)
    lock = HashTimeLockState(
        lock_amount,
        lock_expiration,
        lock_secrethash,
    )

    mediated_transfer = make_receive_transfer_mediated(
        channel_state=channel_state,
        privkey=pkey,
        nonce=1,
        transferred_amount=0,
        lock=lock,
    )

    from_route = factories.route_from_channel(channel_state)
    init_target = ActionInitTarget(
        from_route,
        mediated_transfer,
    )

    node.state_transition(chain_state, init_target)

    closed_block_number = open_block_number + 10
    channel_close_state_change = ContractReceiveChannelClosed(
        factories.make_transaction_hash(),
        channel_state.partner_state.address,
        token_network_state.address,
        channel_state.identifier,
        closed_block_number,
    )

    channel_closed_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_new_iteration.new_state,
        channel_close_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    settle_block_number = closed_block_number + channel_state.settle_timeout + 1
    channel_settled_state_change = ContractReceiveChannelSettled(
        factories.make_transaction_hash(),
        token_network_state.address,
        channel_state.identifier,
        settle_block_number,
    )

    channel_settled_iteration = token_network.state_transition(
        payment_network_identifier,
        channel_closed_iteration.new_state,
        channel_settled_state_change,
        pseudo_random_generator,
        closed_block_number,
    )

    token_network_state_after_settle = channel_settled_iteration.new_state
    ids_to_channels = token_network_state_after_settle.channelidentifiers_to_channels
    assert len(ids_to_channels) == 1
    assert channel_state.identifier in ids_to_channels

    # Create new channel while the previous one is pending unlock
    new_channel_state = factories.make_channel(
        our_balance=our_balance,
        partner_balance=our_balance,
        partner_address=address,
    )
    channel_new_state_change = ContractReceiveChannelNew(
        factories.make_transaction_hash(),
        token_network_state.address,
        new_channel_state,
        closed_block_number + 1,
    )

    channel_new_iteration = token_network.state_transition(
        payment_network_identifier,
        token_network_state,
        channel_new_state_change,
        pseudo_random_generator,
        open_block_number,
    )

    token_network_state_after_new_open = channel_new_iteration.new_state
    ids_to_channels = token_network_state_after_new_open.channelidentifiers_to_channels

    assert len(ids_to_channels) == 2
    assert channel_state.identifier in ids_to_channels


def test_routing_updates(
        token_network_state,
        our_address,
):
    open_block_number = 10
    pseudo_random_generator = random.Random()
    pkey1, address1 = factories.make_privkey_address()
    pkey2, address2 = factories.make_privkey_address()
    pkey3, address3 = factories.make_privkey_address()

    amount = 30
    our_balance = amount + 50
    channel_state = factories.make_channel(
        our_balance=our_balance,
        our_address=our_address,
        partner_balance=our_balance,
        partner_address=address1,
    )
    payment_network_identifier = factories.make_payment_network_identifier()

    # create a new channel as participant, check graph update
    channel_new_state_change = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_state=channel_state,
        block_number=open_block_number,
    )

    channel_new_iteration1 = token_network.state_transition(
        payment_network_identifier=payment_network_identifier,
        token_network_state=token_network_state,
        state_change=channel_new_state_change,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number,
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
        token_network_identifier=token_network_state.address,
        channel_identifier=new_channel_identifier,
        participant1=address2,
        participant2=address3,
        block_number=open_block_number,
    )

    channel_new_iteration2 = token_network.state_transition(
        payment_network_identifier=payment_network_identifier,
        token_network_state=channel_new_iteration1.new_state,
        state_change=channel_new_state_change,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number + 10,
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
    channel_close_state_change1 = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.partner_state.address,
        token_network_identifier=token_network_state.address,
        channel_identifier=channel_state.identifier,
        block_number=closed_block_number,
    )

    channel_closed_iteration1 = token_network.state_transition(
        payment_network_identifier=payment_network_identifier,
        token_network_state=channel_new_iteration2.new_state,
        state_change=channel_close_state_change1,
        pseudo_random_generator=pseudo_random_generator,
        block_number=closed_block_number,
    )

    # Check that a second ContractReceiveChannelClosed events is handled properly
    # This might have been sent from the other participant of the channel
    # See issue #2449
    channel_close_state_change2 = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=channel_state.our_state.address,
        token_network_identifier=token_network_state.address,
        channel_identifier=channel_state.identifier,
        block_number=closed_block_number,
    )

    channel_closed_iteration2 = token_network.state_transition(
        payment_network_identifier=payment_network_identifier,
        token_network_state=channel_closed_iteration1.new_state,
        state_change=channel_close_state_change2,
        pseudo_random_generator=pseudo_random_generator,
        block_number=closed_block_number,
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
        token_network_identifier=token_network_state.address,
        channel_identifier=new_channel_identifier,
        block_number=closed_block_number,
    )

    channel_closed_iteration3 = token_network.state_transition(
        payment_network_identifier=payment_network_identifier,
        token_network_state=channel_closed_iteration2.new_state,
        state_change=channel_close_state_change3,
        pseudo_random_generator=pseudo_random_generator,
        block_number=closed_block_number + 10,
    )

    # Check that a second ContractReceiveRouteClosed events is handled properly.
    # This might have been sent from the second participant of the channel
    # See issue #2449
    channel_close_state_change4 = ContractReceiveRouteClosed(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_identifier=new_channel_identifier,
        block_number=closed_block_number + 10,
    )

    channel_closed_iteration4 = token_network.state_transition(
        payment_network_identifier=payment_network_identifier,
        token_network_state=channel_closed_iteration3.new_state,
        state_change=channel_close_state_change4,
        pseudo_random_generator=pseudo_random_generator,
        block_number=closed_block_number + 10,
    )

    graph_state = channel_closed_iteration4.new_state.network_graph
    assert channel_state.identifier not in graph_state.channel_identifier_to_participants
    assert new_channel_identifier not in graph_state.channel_identifier_to_participants
    assert len(graph_state.channel_identifier_to_participants) == 0
    assert len(graph_state.network.edges()) == 0


def test_routing_issue2663(
        chain_state,
        payment_network_state,
        token_network_state,
        our_address,
):
    open_block_number = 10
    pseudo_random_generator = random.Random()
    pkey1, address1 = factories.make_privkey_address()
    pkey2, address2 = factories.make_privkey_address()
    pkey3, address3 = factories.make_privkey_address()

    # Create a network with the following topology
    #
    # our  ----- 50 ---->  (1)
    #  |                    ^
    #  |                    |
    # 100                  100
    #  |                    |
    #  v                    |
    # (2)  ----- 100 --->  (3)

    channel_state1 = factories.make_channel(
        our_balance=50,
        our_address=our_address,
        partner_balance=0,
        partner_address=address1,
    )
    channel_state2 = factories.make_channel(
        our_balance=100,
        our_address=our_address,
        partner_balance=0,
        partner_address=address2,
    )

    # create new channels as participant
    channel_new_state_change1 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_state=channel_state1,
        block_number=open_block_number,
    )
    channel_new_state_change2 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_state=channel_state2,
        block_number=open_block_number,
    )

    channel_new_iteration1 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=token_network_state,
        state_change=channel_new_state_change1,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number,
    )

    channel_new_iteration2 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration1.new_state,
        state_change=channel_new_state_change2,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number,
    )

    graph_state = channel_new_iteration2.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 2
    assert len(graph_state.network.edges()) == 2

    # create new channels without being participant
    channel_new_state_change3 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_identifier=3,
        participant1=address2,
        participant2=address3,
        block_number=open_block_number,
    )

    channel_new_iteration3 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration2.new_state,
        state_change=channel_new_state_change3,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number + 10,
    )

    graph_state = channel_new_iteration3.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 3
    assert len(graph_state.network.edges()) == 3

    channel_new_state_change4 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_identifier=4,
        participant1=address3,
        participant2=address1,
        block_number=open_block_number,
    )
    channel_new_iteration4 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration3.new_state,
        state_change=channel_new_state_change4,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number + 10,
    )

    graph_state = channel_new_iteration4.new_state.network_graph
    assert len(graph_state.channel_identifier_to_participants) == 4
    assert len(graph_state.network.edges()) == 4

    # test routing with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    routes1 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=50,
        previous_address=None,
    )
    assert routes1[0].node_address == address1
    assert routes1[1].node_address == address2

    routes2 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=51,
        previous_address=None,
    )
    assert routes2[0].node_address == address2

    # test routing with node 2 offline
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_UNREACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    routes1 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=50,
        previous_address=None,
    )
    assert routes1[0].node_address == address1

    routes2 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=51,
        previous_address=None,
    )
    assert routes2 == []

    # test routing with node 3 offline
    # the routing doesn't care as node 3 is not directly connected
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_UNREACHABLE,
    }

    routes1 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=50,
        previous_address=None,
    )
    assert routes1[0].node_address == address1
    assert routes1[1].node_address == address2

    routes2 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=51,
        previous_address=None,
    )
    assert routes2[0].node_address == address2

    # test routing with node 1 offline
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_UNREACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    routes1 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=50,
        previous_address=None,
    )
    # right now the channel to 1 gets filtered out as it is offline
    assert routes1[0].node_address == address2

    routes2 = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address1,
        amount=51,
        previous_address=None,
    )
    assert routes2[0].node_address == address2


def test_routing_priority(
        chain_state,
        payment_network_state,
        token_network_state,
        our_address,
):
    open_block_number = 10
    pseudo_random_generator = random.Random()
    pkey1, address1 = factories.make_privkey_address()
    pkey2, address2 = factories.make_privkey_address()
    pkey3, address3 = factories.make_privkey_address()
    pkey4, address4 = factories.make_privkey_address()

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

    channel_state1 = factories.make_channel(
        our_balance=1,
        our_address=our_address,
        partner_balance=1,
        partner_address=address1,
    )
    channel_state2 = factories.make_channel(
        our_balance=2,
        our_address=our_address,
        partner_balance=0,
        partner_address=address2,
    )

    # create new channels as participant
    channel_new_state_change1 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_state=channel_state1,
        block_number=open_block_number,
    )
    channel_new_state_change2 = ContractReceiveChannelNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_state=channel_state2,
        block_number=open_block_number,
    )

    channel_new_iteration1 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=token_network_state,
        state_change=channel_new_state_change1,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number,
    )

    channel_new_iteration2 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration1.new_state,
        state_change=channel_new_state_change2,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number,
    )

    # create new channels without being participant
    channel_new_state_change3 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_identifier=3,
        participant1=address2,
        participant2=address3,
        block_number=open_block_number,
    )

    channel_new_iteration3 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration2.new_state,
        state_change=channel_new_state_change3,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number + 10,
    )

    channel_new_state_change4 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_identifier=4,
        participant1=address3,
        participant2=address1,
        block_number=open_block_number,
    )

    channel_new_iteration4 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration3.new_state,
        state_change=channel_new_state_change4,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number + 10,
    )

    channel_new_state_change5 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_identifier=4,
        participant1=address3,
        participant2=address4,
        block_number=open_block_number,
    )

    channel_new_iteration5 = token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration4.new_state,
        state_change=channel_new_state_change5,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number + 10,
    )

    channel_new_state_change6 = ContractReceiveRouteNew(
        transaction_hash=factories.make_transaction_hash(),
        token_network_identifier=token_network_state.address,
        channel_identifier=4,
        participant1=address2,
        participant2=address4,
        block_number=open_block_number,
    )

    token_network.state_transition(
        payment_network_identifier=payment_network_state.address,
        token_network_state=channel_new_iteration5.new_state,
        state_change=channel_new_state_change6,
        pseudo_random_generator=pseudo_random_generator,
        block_number=open_block_number + 10,
    )

    # test routing priority with all nodes available
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    routes = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address3,
        amount=1,
        previous_address=None,
    )
    assert routes[0].node_address == address1
    assert routes[1].node_address == address2

    # number of hops overwrites refunding capacity (route over node 2 involves less hops)
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
        address4: NODE_NETWORK_REACHABLE,
    }

    routes = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address4,
        amount=1,
        previous_address=None,
    )
    assert routes[0].node_address == address2
    assert routes[1].node_address == address1

    # sufficient routing capacity overwrites refunding capacity
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_REACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    routes = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address3,
        amount=2,
        previous_address=None,
    )
    assert routes[0].node_address == address2

    # availability overwrites refunding capacity (node 1 offline)
    chain_state.nodeaddresses_to_networkstates = {
        address1: NODE_NETWORK_UNREACHABLE,
        address2: NODE_NETWORK_REACHABLE,
        address3: NODE_NETWORK_REACHABLE,
    }

    routes = get_best_routes(
        chain_state=chain_state,
        token_network_id=token_network_state.address,
        from_address=our_address,
        to_address=address3,
        amount=1,
        previous_address=None,
    )
    assert routes[0].node_address == address2
