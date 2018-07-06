import copy
import random

from raiden.constants import UINT64_MAX
from raiden.tests.utils import factories
from raiden.transfer import channel, token_network
from raiden.transfer.state_change import ContractReceiveChannelNew
from raiden.transfer.state import TokenNetworkState


def test_contract_receive_channelnew_must_be_idempotent():
    block_number = 10
    pseudo_random_generator = random.Random()

    token_network_id = factories.make_address()
    token_id = factories.make_address()
    token_network_state = TokenNetworkState(token_network_id, token_id)

    amount = 30
    our_balance = amount + 50
    channel_state1 = factories.make_channel(our_balance=our_balance)
    channel_state2 = copy.deepcopy(channel_state1)

    state_change1 = ContractReceiveChannelNew(token_network_id, channel_state1)

    token_network.state_transition(
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

    state_change2 = ContractReceiveChannelNew(token_network_id, channel_state2)

    # replay the ContractReceiveChannelNew state change
    iteration = token_network.state_transition(
        token_network_state,
        state_change2,
        pseudo_random_generator,
        block_number,
    )

    msg = 'the channel must not been overwritten'
    channelmap_by_id = iteration.new_state.channelidentifiers_to_channels
    assert channelmap_by_id[channel_state1.identifier] == channel_state1, msg

    channelmap_by_address = iteration.new_state.partneraddresses_to_channels
    assert channelmap_by_address[channel_state1.partner_state.address] == channel_state1, msg
