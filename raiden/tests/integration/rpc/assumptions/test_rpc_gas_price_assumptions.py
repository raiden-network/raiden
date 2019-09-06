import pytest
from eth_utils import to_checksum_address
from web3 import Web3

from raiden.exceptions import ReplacementTransactionUnderpriced, TransactionAlreadyPending
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils import safe_gas_limit
from raiden.utils.typing import Callable, Dict, GasPrice


def make_fixed_gas_price_strategy(gas_price: GasPrice) -> Callable:
    def fixed_gas_price_strategy(_web3: Web3, _transaction_params: Dict) -> GasPrice:
        return gas_price

    return fixed_gas_price_strategy


def make_decreasing_gas_price_strategy(gas_price: GasPrice) -> Callable:
    # this is a really hacky way to create decreasing numbers
    def increasing_gas_price_strategy(web3: Web3, _transaction_params: Dict) -> GasPrice:
        old_counter = getattr(web3, "counter", gas_price)
        web3.counter = old_counter - 1
        return old_counter

    return increasing_gas_price_strategy


def test_duplicated_transaction_same_gas_price_raises(deploy_client: JSONRPCClient) -> None:
    """ If the same transaction is sent twice a JSON RPC error is raised. """
    gas_price = GasPrice(2000000000)
    gas_price_strategy = make_fixed_gas_price_strategy(gas_price)
    deploy_client.web3.eth.setGasPriceStrategy(gas_price_strategy)
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    second_client = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    second_proxy = second_client.new_contract_proxy(
        abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
    )

    check_block = deploy_client.get_checking_block()
    gas_estimate = contract_proxy.estimate_gas(check_block, "ret")
    assert gas_estimate, "Gas estimation should not fail here"
    startgas = safe_gas_limit(gas_estimate)

    contract_proxy.transact("ret", startgas)
    with pytest.raises(TransactionAlreadyPending):
        second_proxy.transact("ret", startgas)


def test_duplicated_transaction_different_gas_price_raises(deploy_client: JSONRPCClient) -> None:
    """ If the same transaction is sent twice a JSON RPC error is raised. """
    gas_price = GasPrice(2000000000)
    deploy_client.web3.eth.setGasPriceStrategy(make_decreasing_gas_price_strategy(gas_price))
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    second_client = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    second_proxy = second_client.new_contract_proxy(
        abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
    )

    check_block = deploy_client.get_checking_block()
    startgas = safe_gas_limit(contract_proxy.estimate_gas(check_block, "ret"))

    with pytest.raises(ReplacementTransactionUnderpriced):
        second_proxy.transact("ret", startgas)
        contract_proxy.transact("ret", startgas)
