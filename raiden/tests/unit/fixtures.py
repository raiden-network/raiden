import random

import pytest

from raiden.tests.utils import factories
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.transfer.state import ChainState, PaymentNetworkState, TokenNetworkState

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
        pseudo_random_generator=random.Random(),
        block_number=block_number,
        block_hash=factories.make_block_hash(),
        our_address=our_address,
        chain_id=UNIT_CHAIN_ID,
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
