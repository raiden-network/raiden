import copy
import random

from raiden.constants import UINT64_MAX
from raiden.tests.utils import factories
from raiden.transfer import node, channel, token_network
from raiden.transfer.state import HashTimeLockState
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
)
from raiden.transfer.mediated_transfer.state_change import ActionInitTarget
from raiden.transfer.state import TokenNetworkState
from raiden.tests.utils.transfer import make_receive_transfer_mediated
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
        channel_state1.our_state.address,
        token_network_id,
        channel_state1,
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
        channel_state2.our_state.address,
        token_network_id,
        channel_state2,
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

    channelmap_by_address = iteration.new_state.partneraddresses_to_channels
    partner_channels = channelmap_by_address[channel_state1.partner_state.address]
    assert partner_channels[channel_state1.identifier] == channel_state1, msg


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
        channel_state.our_state.address,
        token_network_id,
        channel_state,
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
        channel_state.partner_state.address,
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
    )
    payment_network_identifier = factories.make_payment_network_identifier()

    channel_new_state_change = ContractReceiveChannelNew(
        our_address,
        token_network_state.address,
        channel_state,
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
        channel_state,
        pkey,
        1,  # nonce
        0,  # amount
        lock,
        token_network_address=token_network_state.address,
    )

    from_route = factories.route_from_channel(channel_state)
    init_target = ActionInitTarget(
        from_route,
        mediated_transfer,
    )

    node.state_transition(chain_state, init_target)

    closed_block_number = open_block_number + 10
    channel_close_state_change = ContractReceiveChannelClosed(
        token_network_state.address,
        channel_state.identifier,
        channel_state.partner_state.address,
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
        our_address,
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
        our_address,
        token_network_state.address,
        new_channel_state,
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
