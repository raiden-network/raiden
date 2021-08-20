import random
from hashlib import sha256

import pytest
from eth_utils import keccak

from raiden.constants import LOCKSROOT_OF_NO_LOCKS
from raiden.tests.utils import factories
from raiden.tests.utils.transfer import make_receive_transfer_mediated
from raiden.transfer import node, token_network, views
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.transfer.state import (
    HashTimeLockState,
    PendingLocksState,
    RouteState,
    TokenNetworkState,
)
from raiden.transfer.state_change import (
    Block,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
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
        our_transferred_amount=0,
        partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        partner_transferred_amount=0,
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
    assert channel_state.identifier not in ids_to_channels


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
        our_transferred_amount=0,
        partner_onchain_locksroot=compute_locksroot(
            channel_state_after_closed.partner_state.pending_locks
        ),
        partner_transferred_amount=0,
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
    assert len(ids_to_channels) == 0


def test_mediator_clear_pairs_after_batch_unlock(
    chain_state, token_network_state, our_address, channel_properties
):
    """Regression test for https://github.com/raiden-network/raiden/issues/2932
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
        route=[channel_state.our_state.address, channel_state.partner_state.address]
    )
    from_hop = factories.make_hop_from_channel(channel_state)
    init_mediator = ActionInitMediator(
        candidate_route_states=[route_state],
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
        our_transferred_amount=0,
        partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        partner_transferred_amount=0,
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
        our_transferred_amount=0,
        partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        partner_transferred_amount=0,
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
