import pytest

from raiden.exceptions import InsufficientEth
from raiden.network.rpc.client import (
    JSONRPCClient,
    SmartContractCall,
    TransactionEstimated,
    gas_price_for_fast_transaction,
)
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils.smart_contracts import safe_gas_limit


def test_transact_opcode(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that did not throw is 0x1 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.getCode(address)) > 0

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "ret", {})
    assert estimated_transaction
    estimated_transaction.estimated_gas *= 2

    transaction_hash = deploy_client.transact(estimated_transaction)
    receipt = deploy_client.poll_transaction(transaction_hash)

    assert check_transaction_threw(receipt=receipt) is None, "must be empty"


def test_transact_throws_opcode(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that hit an assert or require is 0x0 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.getCode(address)) > 0

    # the method always fails, so the gas estimation returns 0 here, using a
    # hardcoded a value to circumvent gas estimation.
    estimated_gas = safe_gas_limit(22000)
    gas_price = gas_price_for_fast_transaction(deploy_client.web3)

    block = deploy_client.get_block("latest")

    estimated_transaction_fail_assert = TransactionEstimated(
        from_address=address,
        data=SmartContractCall(contract_proxy, "fail_assert", (), {}, value=0),
        eth_node=deploy_client.eth_node,
        extra_log_details={},
        estimated_gas=estimated_gas,
        gas_price=gas_price,
        approximate_block=(block["hash"], block["number"]),
    )
    transaction_hash = deploy_client.transact(estimated_transaction_fail_assert)
    receipt = deploy_client.poll_transaction(transaction_hash)

    assert check_transaction_threw(receipt=receipt), "must not be empty"

    estimated_transaction_fail_require = TransactionEstimated(
        from_address=address,
        data=SmartContractCall(contract_proxy, "fail_require", (), {}, value=0),
        eth_node=deploy_client.eth_node,
        extra_log_details={},
        estimated_gas=estimated_gas,
        gas_price=gas_price,
        approximate_block=(block["hash"], block["number"]),
    )
    transaction_hash = deploy_client.transact(estimated_transaction_fail_require)
    receipt = deploy_client.poll_transaction(transaction_hash)

    assert check_transaction_threw(receipt=receipt), "must not be empty"


def test_transact_opcode_oog(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.getCode(address)) > 0

    # divide the estimate by 2 to run into out-of-gas
    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "loop", {}, 1000)
    assert estimated_transaction
    estimated_transaction.estimated_gas //= 2

    transaction = deploy_client.transact(estimated_transaction)
    receipt = deploy_client.poll_transaction(transaction)

    assert check_transaction_threw(receipt=receipt), "must not be empty"


def test_transact_fails_if_the_account_does_not_have_enough_eth_to_pay_for_the_gas(
    deploy_client: JSONRPCClient
) -> None:
    """ The gas estimation does not fail if the transaction execution requires
    more gas then the account's eth balance. However sending the transaction
    will.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "loop", {}, 1000)
    assert estimated_transaction, "The gas estimation should not have failed."

    burn_eth(deploy_client, amount_to_leave=estimated_transaction.estimated_gas // 2)
    with pytest.raises(InsufficientEth):
        deploy_client.transact(estimated_transaction)
