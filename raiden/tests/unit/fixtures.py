import random

import pytest

from raiden.tests.utils import factories
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.transfer.state import ChainState, PaymentNetworkState, TokenNetworkState

# ob-review - AFAICT there is noe outer name being redefined
# pylint: disable=redefined-outer-name


@pytest.fixture
def our_address():
    return factories.make_address()


@pytest.fixture
def token_id():
    return factories.make_address()


@pytest.fixture
def token_network_id():
    return factories.make_address()


@pytest.fixture
def payment_network_id():
    return factories.make_address()


@pytest.fixture
def chain_state(our_address):
    block_number = 1

    return ChainState(
        random.Random(),
        block_number,
        our_address,
        UNIT_CHAIN_ID,
    )


@pytest.fixture
def payment_network_state(chain_state, payment_network_id):
    payment_network = PaymentNetworkState(
        payment_network_id,
        [],
    )
    chain_state.identifiers_to_paymentnetworks[payment_network_id] = payment_network
    return payment_network


@pytest.fixture
def token_network_state(payment_network_state, token_network_id, token_id):
    token_network = TokenNetworkState(
        token_network_id,
        token_id,
    )
    payment_network_state.tokenidentifiers_to_tokennetworks[token_network_id] = token_network
    payment_network_state.tokenaddresses_to_tokenidentifiers[token_id] = token_network_id

    return token_network

# ob-review
# This feels to me a bit like a fixture dependency labyrinth
# chain_state <- our_adress
# token_network_state <- payment_network_state <- chain_state
# also directly depends directly on payment_network_state
# This would make for an interesting graph and to a newcomer like me this is at the very
# least very confusing.
#
# I also am confused how this is o.k. to depend on e.g. different chain_states that
# are all function scope and therefore have all different values for our_address
@pytest.fixture
def netting_channel_state(chain_state, token_network_state, payment_network_state):
    partner = factories.make_address()
    channel_id = factories.make_channel_identifier()
    channel_state = factories.make_channel(
        our_balance=10,
        partner_balance=10,
        our_address=chain_state.our_address,
        partner_address=partner,
        token_address=token_network_state.token_address,
        payment_network_identifier=payment_network_state.address,
        token_network_identifier=token_network_state.address,
        channel_identifier=channel_id,
    )

    token_network_state.partneraddresses_to_channelidentifiers[partner].append(channel_id)
    token_network_state.channelidentifiers_to_channels[channel_id] = channel_state

    return channel_state
