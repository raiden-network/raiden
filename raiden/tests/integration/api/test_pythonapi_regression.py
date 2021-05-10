import pytest

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import BLOCK_ID_LATEST
from raiden.raiden_service import RaidenService
from raiden.tests.utils import factories
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.transfer import block_offset_timeout, watch_for_unlock_failures
from raiden.utils.typing import List, PaymentAmount, PaymentID, TargetAddress


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_close_regression(raiden_network: List[RaidenService], deposit, token_addresses, pfs_mock):
    """The python api was using the wrong balance proof to close the channel,
    thus the close was failing if a transfer was made.
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    pfs_mock.add_apps(raiden_network)

    api1 = RaidenAPI(app0)
    api2 = RaidenAPI(app1)

    registry_address = app0.default_registry.address
    channel_list = api1.get_channel_list(registry_address, token_address, app1.address)
    channel12 = channel_list[0]

    token_proxy = app0.proxy_manager.token(token_address, BLOCK_ID_LATEST)
    node1_balance_before = token_proxy.balance_of(api1.address)
    node2_balance_before = token_proxy.balance_of(api2.address)

    # Initialize app2 balance proof and close the channel
    amount = PaymentAmount(10)
    identifier = PaymentID(42)
    secret, secrethash = factories.make_secret_with_hash()
    timeout = block_offset_timeout(app1, "Transfer timed out.")
    with watch_for_unlock_failures(*raiden_network), timeout:
        assert api1.transfer_and_wait(
            registry_address=registry_address,
            token_address=token_address,
            amount=amount,
            target=TargetAddress(api2.address),
            identifier=identifier,
            secret=secret,
        )
        timeout.exception_to_throw = ValueError(
            "Waiting for transfer received success in the WAL timed out."
        )
        result = waiting.wait_for_received_transfer_result(
            raiden=app1,
            payment_identifier=identifier,
            amount=amount,
            retry_timeout=app1.alarm.sleep_time,
            secrethash=secrethash,
        )

    msg = f"Unexpected transfer result: {str(result)}"
    assert result == waiting.TransferWaitResult.UNLOCKED, msg

    api2.channel_close(registry_address, token_address, api1.address)

    waiting.wait_for_settle(
        app0,
        app0.default_registry.address,
        token_address,
        [channel12.identifier],
        app0.alarm.sleep_time,
    )
    node1_expected_balance = node1_balance_before + deposit - amount
    node2_expected_balance = node2_balance_before + deposit + amount
    assert token_proxy.balance_of(api1.address) == node1_expected_balance
    assert token_proxy.balance_of(api2.address) == node2_expected_balance
