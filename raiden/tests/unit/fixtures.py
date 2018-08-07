import pytest
import random

from raiden.transfer.state import (
    ChainState,
    PaymentNetworkState,
    TokenNetworkState,
)

from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    UNIT_CHAIN_ID,
)

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
    payment_network_state.tokenaddresses_to_tokennetworks[token_id] = token_network

    return token_network
