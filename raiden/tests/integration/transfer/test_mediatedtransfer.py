import pytest

from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    wait_assert,
    mediated_transfer,
)
from raiden.transfer import views


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes,
    )

    wait_assert(
        token_network_identifier,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
        func=assert_synched_channel_state,
        timeout=network_wait,
    )
    wait_assert(
        token_network_identifier,
        app1, deposit - amount, [],
        app2, deposit + amount, [],
        func=assert_synched_channel_state,
        timeout=network_wait,
    )


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer_with_entire_deposit(
        raiden_network,
        number_of_nodes,
        token_addresses,
        deposit,
        network_wait,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        deposit,
        timeout=network_wait * number_of_nodes,
    )

    mediated_transfer(
        app2,
        app0,
        token_network_identifier,
        deposit * 2,
        timeout=network_wait * number_of_nodes,
    )

    wait_assert(
        token_network_identifier,
        app0, deposit * 2, [],
        app1, 0, [],
        func=assert_synched_channel_state,
        timeout=network_wait,
    )
    wait_assert(
        token_network_identifier,
        app1, deposit * 2, [],
        app2, 0, [],
        func=assert_synched_channel_state,
        timeout=network_wait,
    )
