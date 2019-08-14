import gevent
import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.tests.utils import factories
from raiden.tests.utils.detect_failure import raise_on_failure


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_close_regression(raiden_network, deposit, token_addresses):
    """ The python api was using the wrong balance proof to close the channel,
    thus the close was failing if a transfer was made.
    """
    raise_on_failure(
        raiden_network,
        run_test_close_regression,
        raiden_network=raiden_network,
        deposit=deposit,
        token_addresses=token_addresses,
    )


def run_test_close_regression(raiden_network, deposit, token_addresses):
    app0, app1 = raiden_network
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
    secret, secrethash = factories.make_secret_with_hash()
    assert api1.transfer_and_wait(
        registry_address=registry_address,
        token_address=token_address,
        amount=amount,
        target=api2.address,
        identifier=identifier,
        secret=secret,
        transfer_timeout=10,
    )
    exception = ValueError("Waiting for transfer received success in the WAL timed out")
    with gevent.Timeout(seconds=5, exception=exception):
        result = waiting.wait_for_received_transfer_result(
            raiden=app1.raiden,
            payment_identifier=identifier,
            amount=amount,
            retry_timeout=app1.raiden.alarm.sleep_time,
            secrethash=secrethash,
        )
        msg = f"Unexpected transfer result: {str(result)}"
        assert result == waiting.TransferWaitResult.UNLOCKED, msg

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
