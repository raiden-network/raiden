import gevent
import pytest

from raiden.tests.utils.transfer import assert_synced_channel_state, direct_transfer
from raiden.transfer import views
from raiden.waiting import wait_for_transfer_success


@pytest.mark.parametrize('number_of_nodes', [2])
def test_direct_transfer(raiden_network, token_addresses, deposit, network_wait):
    token_address = token_addresses[0]
    app0, app1 = raiden_network

    amount = 10
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )
    direct_transfer(
        app0,
        app1,
        token_network_identifier,
        amount,
        timeout=network_wait,
    )

    assert_synced_channel_state(
        token_network_identifier,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_direct_transfer_to_offline_node(raiden_network, token_addresses, deposit):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )
    app1.raiden.stop()

    amount = 10
    target = app1.raiden.address
    payment_identifier = 13
    app0.raiden.direct_transfer_async(
        token_network_identifier,
        amount,
        target,
        identifier=payment_identifier,
    )

    app1.raiden.start()
    exception = ValueError('Waiting for transfer received success in the WAL timed out')
    with gevent.Timeout(seconds=60, exception=exception):
        wait_for_transfer_success(
            app1.raiden,
            payment_identifier,
            amount,
            app1.raiden.alarm.sleep_time,
        )

    no_outstanding_locks = []
    assert_synced_channel_state(
        token_network_identifier,
        app0, deposit - amount, no_outstanding_locks,
        app1, deposit + amount, no_outstanding_locks,
    )
