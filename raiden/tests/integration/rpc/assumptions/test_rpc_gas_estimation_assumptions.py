import pytest

from raiden.constants import BLOCK_ID_LATEST, RECEIPT_FAILURE_CODE
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract

SSTORE_COST = 20000


def test_estimate_gas_fail(deploy_client: JSONRPCClient) -> None:
    """ A JSON RPC estimate gas call for a throwing transaction returns None"""
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    msg = "Estimate gas should return None if the transaction hit an assert"
    assert deploy_client.estimate_gas(contract_proxy, "fail_assert", {}) is None, msg

    msg = "Estimate gas should return None if the transaction hit a revert."
    assert deploy_client.estimate_gas(contract_proxy, "fail_require", {}) is None, msg


@pytest.mark.skip(reason="Flaky, see https://github.com/raiden-network/raiden/issues/6261")
def test_estimate_gas_fails_if_startgas_is_higher_than_blockgaslimit(
    deploy_client: JSONRPCClient,
) -> None:
    """Gas estimation fails if the transaction execution requires more gas
    than the block's gas limit.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")

    latest_block_hash = deploy_client.blockhash_from_blocknumber(BLOCK_ID_LATEST)
    current_gas_limit = deploy_client.get_block(latest_block_hash)["gasLimit"]

    # This number of iterations is an over estimation to accomodate for races,
    # this cannot be significantly large because on parity it is a blocking
    # call.
    number_iterations = current_gas_limit // SSTORE_COST

    # This race condition cannot be fixed because geth does not support
    # block_identifier for eth_estimateGas. The test should not be flaky
    # because number_iterations is order of magnitudes larger then it needs to
    # be
    estimated_transaction = deploy_client.estimate_gas(
        contract_proxy, "waste_storage", {}, number_iterations
    )
    msg = "estimate_gas must return empty if sending the transaction would fail"
    assert estimated_transaction is None, msg


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

    estimated_first_transaction = deploy_client.estimate_gas(
        contract_proxy, "gas_increase_exponential", {}
    )
    assert estimated_first_transaction, "gas estimation should not have failed"
    first_tx = deploy_client.transact(estimated_first_transaction)

    estimated_second_transaction = deploy_client.estimate_gas(
        contract_proxy, "gas_increase_exponential", {}
    )
    assert estimated_second_transaction, "gas estimation should not have failed"
    second_tx = deploy_client.transact(estimated_second_transaction)

    first_receipt = deploy_client.poll_transaction(first_tx).receipt
    second_receipt = deploy_client.poll_transaction(second_tx).receipt

    assert (
        second_receipt["gasLimit"]  # type: ignore
        < deploy_client.get_block(BLOCK_ID_LATEST)["gasLimit"]
    )
    assert first_receipt["status"] != RECEIPT_FAILURE_CODE
    assert second_receipt["status"] != RECEIPT_FAILURE_CODE


def test_estimate_gas_for_dependent_transactions_needs_a_mined_transaction(
    deploy_client: JSONRPCClient,
) -> None:
    """Gas estimation for a transaction that depends on another works after
    the first is mined and confirmed.

    This is not sufficient (as of geth 1.9.10):

    - eth_getTransaction returning the transaction

    This test makes sure that consecutive transactions which depends on the
    changes from pending ones can have their gas estimate after
    `eth_getTransaction` returns. This assumption is important for the fast
    handling of `approve` and `setTotalDeposit` transactions, where the
    `setTotalDeposit` needs the result of an estimate_gas just after sending an
    approve transaction.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")

    iterations = 100

    for next_counter in range(1, 20):
        transaction = deploy_client.estimate_gas(
            contract_proxy, "next", {}, next_counter, iterations
        )
        msg = (
            "gas estimation should not have failed, this means the side-effects "
            "of the previous transaction have not been accounted for and the "
            "strategy of polling is not sufficient to avoid race conditions."
        )
        assert transaction, msg

        transaction_hash = deploy_client.transact(transaction)

        # This does not work:
        #
        # tx_receipt = None
        # while tx_receipt is None:
        #     try:
        #         tx_receipt = deploy_client.web3.eth.getTransaction(transaction_hash)
        #     except TransactionNotFound:
        #         pass

        # Neither `eth_getTransaction` and `eth_pendingTransactions` are
        # sufficient here, it still possible to have race conditoins with both
        # of these RPC calls.
        deploy_client.poll_transaction(transaction_hash)
