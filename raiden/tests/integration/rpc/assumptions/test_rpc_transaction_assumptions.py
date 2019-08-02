import pytest
from eth_utils import to_checksum_address

from raiden.exceptions import InsufficientFunds
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils import safe_gas_limit


def test_transact_opcode(deploy_client):
    """ The receipt status field of a transaction that did not throw is 0x1 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    check_block = deploy_client.get_checking_block()
    startgas = contract_proxy.estimate_gas(check_block, "ret") * 2

    transaction = contract_proxy.transact("ret", startgas)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt) is None, "must be empty"


def test_transact_throws_opcode(deploy_client):
    """ The receipt status field of a transaction that hit an assert or require is 0x0 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    # the gas estimation returns 0 here, so hardcode a value
    startgas = safe_gas_limit(22000)

    transaction = contract_proxy.transact("fail_assert", startgas)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt), "must not be empty"

    transaction = contract_proxy.transact("fail_require", startgas)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt), "must not be empty"


def test_transact_opcode_oog(deploy_client):
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    # divide the estimate by 2 to run into out-of-gas
    check_block = deploy_client.get_checking_block()
    startgas = safe_gas_limit(contract_proxy.estimate_gas(check_block, "loop", 1000)) // 2

    transaction = contract_proxy.transact("loop", startgas, 1000)
    receipt = deploy_client.poll(transaction)

    assert check_transaction_threw(receipt=receipt), "must not be empty"


def test_transact_fail_if_the_account_does_not_have_enough_eth_to_pay_for_thegas(deploy_client):
    """ The gas estimation does not fail if the transaction execution requires
    more gas then the account's eth balance. However sending the transaction
    will.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    check_block = deploy_client.get_checking_block()

    startgas = contract_proxy.estimate_gas(check_block, "loop", 1000)
    assert startgas, "The gas estimation should not have failed."

    burn_eth(deploy_client, amount_to_leave=startgas // 2)
    with pytest.raises(InsufficientFunds):
        contract_proxy.transact("loop", startgas, 1000)
