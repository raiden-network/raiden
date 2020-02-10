import pytest

from raiden.constants import RECEIPT_FAILURE_CODE
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils.formatting import to_checksum_address

SSTORE_COST = 20000


def test_estimate_gas_fail(deploy_client: JSONRPCClient) -> None:
    """ A JSON RPC estimate gas call for a throwing transaction returns None"""
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    check_block = deploy_client.get_checking_block()

    msg = "Estimate gas should return None if the transaction hit an assert"
    assert contract_proxy.estimate_gas(check_block, "fail_assert") is None, msg

    msg = "Estimate gas should return None if the transaction hit a revert."
    assert contract_proxy.estimate_gas(check_block, "fail_require") is None, msg


def test_estimate_gas_fails_if_startgas_is_higher_than_blockgaslimit(
    deploy_client: JSONRPCClient,
) -> None:
    """ Gas estimation fails if the transaction execution requires more gas
    than the block's gas limit.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")

    latest_block_hash = deploy_client.blockhash_from_blocknumber("latest")
    current_gas_limit = deploy_client.get_block(latest_block_hash)["gasLimit"]

    # This number of iterations is an over estimation to accomodate for races,
    # this cannot be significantly large because on parity it is a blocking
    # call.
    number_iterations = current_gas_limit // SSTORE_COST

    # This race condition cannot be fixed because geth does not support
    # block_identifier for eth_estimateGas. The test should not be flaky
    # because number_iterations is order of magnitudes larger then it needs to
    # be
    block_identifier = None

    startgas = contract_proxy.estimate_gas(block_identifier, "waste_storage", number_iterations)
    assert startgas is None, "estimate_gas must return empty if sending the transaction would fail"


@pytest.mark.xfail(reason="The pending block is not taken into consideration")
def test_estimate_gas_defaults_to_pending(deploy_client: JSONRPCClient) -> None:
    """Estimating gas without an explicit block identifier always return an
    usable value.

    This test makes sure that the gas estimation works as expected (IOW, it
    will produce a value that can be used for start_gas and the transaction
    will be mined).

    This test was added because the clients Geth and Parity diverge in their
    estimate_gas interface. Geth never accepts a block_identifier for
    eth_estimateGas, and Parity rejects anything but `latest` if it is run with
    `--pruning=fast`.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")

    first_gas = contract_proxy.estimate_gas("pending", "gas_increase_exponential")
    assert first_gas, "gas estimation should not have failed"
    first_tx = contract_proxy.transact("gas_increase_exponential", first_gas)

    second_gas = contract_proxy.estimate_gas("pending", "gas_increase_exponential")
    assert second_gas, "gas estimation should not have failed"
    second_tx = contract_proxy.transact("gas_increase_exponential", second_gas)

    first_receipt = deploy_client.poll(first_tx)
    second_receipt = deploy_client.poll(second_tx)

    assert second_receipt["gasLimit"] < deploy_client.get_block("latest")["gasLimit"]
    assert first_receipt["status"] != RECEIPT_FAILURE_CODE
    assert second_receipt["status"] != RECEIPT_FAILURE_CODE


def test_estimate_gas_for_dependent_transactions_needs_a_mined_transaction(
    deploy_client: JSONRPCClient,
) -> None:
    """Gas estimation for a transaction that depends on another works afte
    eth_getTransaction returns a valid value.

    This test makes sure that consecutive transactions which depends on the
    changes from pending ones can have their gas estimate after
    `eth_getTransaction` returns. This assumption is important for the fast
    handling of `approve` and `setTotalDeposit` transactions, where the
    `setTotalDeposit` needs the result of an estimate_gas just after sending an
    approve transaction.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")

    next_counter = 0
    iterations = 100

    # Do enough transactions so that they won't fit in a single block.
    for _ in range(20):
        next_counter += 1

        gaslimit = contract_proxy.estimate_gas("pending", "next", next_counter, iterations)
        msg = (
            "gas estimation should not have failed, this means the side-effects "
            "of the previous transaction have not been accounted for and the "
            "strategy of polling is not sufficient to avoid race conditins."
        )
        assert gaslimit, msg

        tx = contract_proxy.transact("next", gaslimit, next_counter, iterations)

        # Neither `eth_getTransaction` and `eth_pendingTransactions` are
        # sufficient here, it still possible to have race conditoins with both
        # of these RPC calls.
        deploy_client.poll(tx)
