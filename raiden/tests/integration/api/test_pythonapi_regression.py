import gevent
import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_close_regression(raiden_network, deposit, token_addresses):
    """ The python api was using the wrong balance proof to close the channel,
    thus the close was failing if a transfer was made.
    """
    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]

    api1 = RaidenAPI(app0.raiden)
    api2 = RaidenAPI(app1.raiden)

    registry_address = app0.raiden.default_registry.address
    channel_list = api1.get_channel_list(registry_address, token_address, app1.raiden.address)
    channel12 = channel_list[0]

    token_proxy = app0.raiden.chain.token(token_address)
    node1_balance_before = token_proxy.balance_of(api1.address)
    node2_balance_before = token_proxy.balance_of(api2.address)

    # Initialize app2 balance proof and close the channel
    amount = 10
    identifier = 42
    assert api1.transfer(
        registry_address,
        token_address,
        amount,
        api2.address,
        identifier=identifier,
    )
    exception = ValueError('Waiting for transfer received success in the WAL timed out')
    with gevent.Timeout(seconds=5, exception=exception):
        waiting.wait_for_transfer_success(
            app1.raiden,
            identifier,
            amount,
            app1.raiden.alarm.sleep_time,
        )

    api2.channel_close(registry_address, token_address, api1.address)

    waiting.wait_for_settle(
        app0.raiden,
        app0.raiden.default_registry.address,
        token_address,
        [channel12.identifier],
        app0.raiden.alarm.sleep_time,
    )
    node1_expected_balance = node1_balance_before + deposit - amount
    node2_expected_balance = node2_balance_before + deposit + amount
    assert token_proxy.balance_of(api1.address) == node1_expected_balance
    assert token_proxy.balance_of(api2.address) == node2_expected_balance
