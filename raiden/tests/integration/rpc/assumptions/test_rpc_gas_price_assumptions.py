import gevent
import pytest
from eth_utils import to_checksum_address
from web3 import HTTPProvider, Web3

from raiden.constants import RECEIPT_FAILURE_CODE
from raiden.exceptions import ReplacementTransactionUnderpriced, TransactionAlreadyPending
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils import safe_gas_limit
from raiden.utils.typing import Callable, Dict, GasPrice, List, Port, PrivateKey


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


def test_local_transaction_with_zero_gasprice_is_mined(deploy_client: JSONRPCClient) -> None:
    """ If a transaction is sent through the eth_sendRawTransaction interface,
    directly to the miner, with a gas price of zero, it is considered local and
    mined anyways.
    """
    normal_gas_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    gas_price = GasPrice(0)
    gas_price_strategy = make_fixed_gas_price_strategy(gas_price)
    deploy_client.web3.eth.setGasPriceStrategy(gas_price_strategy)
    zero_gas_proxy = deploy_client.new_contract_proxy(
        abi=normal_gas_proxy.contract.abi, contract_address=normal_gas_proxy.contract_address
    )

    address = normal_gas_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    check_block = deploy_client.get_checking_block()
    gas_estimate = zero_gas_proxy.estimate_gas(check_block, "ret")
    assert gas_estimate, "Gas estimation should not fail here"

    zerogas_txhash = zero_gas_proxy.transact("ret", gas_estimate)
    zerogas_receipt = deploy_client.poll(zerogas_txhash)
    zerogas_tx = deploy_client.web3.eth.getTransaction(zerogas_txhash)

    msg = "Even thought the transaction had a zero gas price, it is not removed from the pool"
    assert zerogas_tx is not None, msg

    msg = "Even though the transaction had gas price of zero, it did get mined."
    assert zerogas_receipt["status"] != RECEIPT_FAILURE_CODE, msg


@pytest.mark.parametrize("blockchain_number_of_nodes", [2])
def test_remote_transaction_with_zero_gasprice_is_not_mined(
    web3: Web3, deploy_key: PrivateKey, blockchain_rpc_ports: List[Port], blockchain_type: str
) -> None:
    """ If the non-local transaction is sent with a gas price set to zero it is
    not mined.
    """
    host = "127.0.0.1"
    miner_rpc_port, rpc_port = blockchain_rpc_ports

    miner_web3 = Web3(HTTPProvider(f"http://{host}:{miner_rpc_port}"))
    miner_client = JSONRPCClient(miner_web3, deploy_key)

    web3 = Web3(HTTPProvider(f"http://{host}:{rpc_port}"))
    client = JSONRPCClient(web3, deploy_key)

    before_deploy_block = client.block_number()
    normal_gas_proxy, _ = deploy_rpc_test_contract(client, "RpcTest")
    num_blocks_to_wait = client.block_number() - before_deploy_block

    gas_price = GasPrice(0)
    gas_price_strategy = make_fixed_gas_price_strategy(gas_price)
    client.web3.eth.setGasPriceStrategy(gas_price_strategy)
    zero_gas_proxy = client.new_contract_proxy(
        abi=normal_gas_proxy.contract.abi, contract_address=normal_gas_proxy.contract_address
    )

    address = normal_gas_proxy.contract_address
    assert len(client.web3.eth.getCode(to_checksum_address(address))) > 0

    check_block = client.get_checking_block()
    gas_estimate = zero_gas_proxy.estimate_gas(check_block, "ret")
    assert gas_estimate, "Gas estimation should not fail here"

    zerogas_txhash = zero_gas_proxy.transact("ret", gas_estimate)

    # wait for how many blocks it took to mine the deployment, since this is a
    # private chain, if the new transaction will be mined it should be roughly
    # in the same time frame (adding two blocks to cover race conditions)
    target_block_number = client.block_number() + num_blocks_to_wait + 2
    while client.block_number() < target_block_number:
        gevent.sleep(0.5)

    miner_zerogas_tx = miner_client.web3.eth.getTransaction(zerogas_txhash)
    miner_zerogas_receipt = miner_client.web3.eth.getTransactionReceipt(zerogas_txhash)

    msg = "The transaction was discarded by the miner, there is no transaction and no receipt"
    assert miner_zerogas_tx is None, msg
    assert miner_zerogas_receipt is None, msg

    zerogas_tx = client.web3.eth.getTransaction(zerogas_txhash)
    zerogas_receipt = client.web3.eth.getTransactionReceipt(zerogas_txhash)

    msg = (
        "The transaction was NOT discarded by the original node, because it is a local transaction"
    )
    assert zerogas_tx is not None, msg

    zerogas_receipt = client.web3.eth.getTransactionReceipt(zerogas_txhash)
    msg = "The transaction does NOT have a receipt because the miner rejected it"

    if blockchain_type == "geth":
        assert zerogas_receipt is None, msg
    elif blockchain_type == "parity":
        assert zerogas_receipt["blockNumber"] is None, msg
    else:
        raise RuntimeError(f"Unknown blockchain_type {blockchain_type}")


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
