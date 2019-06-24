import pytest
from eth_utils import to_checksum_address

from raiden.exceptions import InsufficientFunds
from raiden.network.rpc.transactions import check_transaction_threw
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
    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction) is None, "must be empty"


def test_transact_throws_opcode(deploy_client):
    """ The receipt status field of a transaction that threw is 0x0 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    # the gas estimation returns 0 here, so hardcode a value
    startgas = safe_gas_limit(22000)

    transaction = contract_proxy.transact("fail", startgas)
    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction), "must not be empty"


def test_transact_opcode_oog(deploy_client):
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    # divide the estimate by 2 to run into out-of-gas
    check_block = deploy_client.get_checking_block()
    startgas = safe_gas_limit(contract_proxy.estimate_gas(check_block, "loop", 1000)) // 2

    transaction = contract_proxy.transact("loop", startgas, 1000)
    deploy_client.poll(transaction)

    assert check_transaction_threw(deploy_client, transaction), "must not be empty"


GETH_GAS_PRICE = 1_000_000_000
GETH_GAS_DEPLOY = 213105 * GETH_GAS_PRICE
GETH_GAS_LOOP = 93864 * GETH_GAS_PRICE
GETH_GAS_ACCOUNT_FAIL = GETH_GAS_DEPLOY + GETH_GAS_LOOP // 2
PARITY_GAS_ACCOUNT_FAIL = GETH_GAS_ACCOUNT_FAIL * 4


@pytest.mark.parametrize("account_genesis_eth_balance", [GETH_GAS_ACCOUNT_FAIL])
def test_geth_transact_fail_if_the_account_does_not_have_enough_eth_to_pay_for_thegas(
    deploy_client, skip_if_not_geth  # pylint: disable=unused-argument
):
    """ The gas estimation does not fail if the transaction execution requires
    more gas then the account's eth balance. However sending the transaction
    will.
    """
    run_transact_fail_if_the_account_does_not_have_enough_eth_to_pay_for_thegas(deploy_client)


@pytest.mark.parametrize("account_genesis_eth_balance", [PARITY_GAS_ACCOUNT_FAIL])
def test_parity_transact_fail_if_the_account_does_not_have_enough_eth_to_pay_for_thegas(
    deploy_client, skip_if_not_parity  # pylint: disable=unused-argument
):
    """ The gas estimation does not fail if the transaction execution requires
    more gas then the account's eth balance. However sending the transaction
    will.
    """
    run_transact_fail_if_the_account_does_not_have_enough_eth_to_pay_for_thegas(deploy_client)


def run_transact_fail_if_the_account_does_not_have_enough_eth_to_pay_for_thegas(deploy_client):
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    check_block = deploy_client.get_checking_block()

    startgas = contract_proxy.estimate_gas(check_block, "loop", 1000)
    assert startgas, "The gas estimation should not have failed."

    with pytest.raises(InsufficientFunds):
        contract_proxy.transact("loop", startgas, 1000)
