import pytest

from raiden.exceptions import InsufficientEth
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils.smart_contracts import safe_gas_limit


def test_transact_opcode(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that did not throw is 0x1 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.getCode(address)) > 0

    check_block = deploy_client.get_checking_block()
    startgas = deploy_client.estimate_gas(contract_proxy, check_block, "ret")
    assert startgas
    startgas = startgas * 2

    transaction = deploy_client.transact(contract_proxy, "ret", startgas)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt) is None, "must be empty"


def test_transact_throws_opcode(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that hit an assert or require is 0x0 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.getCode(address)) > 0

    # the gas estimation returns 0 here, so hardcode a value
    startgas = safe_gas_limit(22000)

    transaction = deploy_client.transact(contract_proxy, "fail_assert", startgas)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt), "must not be empty"

    transaction = deploy_client.transact(contract_proxy, "fail_require", startgas)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt), "must not be empty"


def test_transact_opcode_oog(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.getCode(address)) > 0

    # divide the estimate by 2 to run into out-of-gas
    check_block = deploy_client.get_checking_block()
    startgas = deploy_client.estimate_gas(contract_proxy, check_block, "loop", 1000)
    assert startgas
    startgas = safe_gas_limit(startgas) // 2

    transaction = deploy_client.transact(contract_proxy, "loop", startgas, 1000)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt), "must not be empty"


def test_transact_fails_if_the_account_does_not_have_enough_eth_to_pay_for_the_gas(
    deploy_client: JSONRPCClient
) -> None:
    """ The gas estimation does not fail if the transaction execution requires
    more gas then the account's eth balance. However sending the transaction
    will.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    check_block = deploy_client.get_checking_block()

    startgas = deploy_client.estimate_gas(contract_proxy, check_block, "loop", 1000)
    assert startgas, "The gas estimation should not have failed."

    burn_eth(deploy_client, amount_to_leave=startgas // 2)
    with pytest.raises(InsufficientEth):
        deploy_client.transact(contract_proxy, "loop", startgas, 1000)
