import pytest

from raiden.constants import EthClient
from raiden.network.rpc.smartcontract_proxy import ClientErrorInspectResult, inspect_client_error
from raiden.network.rpc.transactions import check_transaction_threw


def test_inspect_client_error():
    """Regression test for issue https://github.com/raiden-network/raiden/issues/3005"""
    errorstr = (
        "{'code': -32015, 'message': 'Transaction execution error.', 'data': "
        "'Internal(\"Requires higher than upper limit of 80000000\")'}"
    )
    exception = ValueError(errorstr)

    result = inspect_client_error(exception, EthClient.PARITY)
    assert result == ClientErrorInspectResult.ALWAYS_FAIL


def test_check_transaction_threw_old_status():
    """Test that an assertion is thrown if transaction receipt is pre-Byzantium"""
    with pytest.raises(AssertionError):
        check_transaction_threw({"this": "is", "a": "receipt", "without": "status"})
