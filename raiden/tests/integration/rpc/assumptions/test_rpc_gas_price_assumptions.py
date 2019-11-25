import gevent
import pytest
from eth_utils import to_checksum_address
from web3 import HTTPProvider, Web3

from raiden.constants import RECEIPT_FAILURE_CODE
from raiden.exceptions import EthereumNonceTooLow, ReplacementTransactionUnderpriced
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


def test_resending_pending_transaction_raises(deploy_client: JSONRPCClient) -> None:
    """ If a pending transaction is re-sent the exception `EthereumNonceTooLow` is raised.

    This tests is only sufficient because of the companion test
    `test_resending_mined_transaction_raises` which shows that if the
    transaction has been mined a different exception is raised.
    """
    # Use a _fixed_ gas price strategy so that both transactions are identical.
    deploy_client.web3.eth.setGasPriceStrategy(make_fixed_gas_price_strategy(GasPrice(2000000000)))
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    # Create a new instance of the JSONRPCClient, this will store the current available nonce
    client_invalid_nonce = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    check_block = deploy_client.get_checking_block()
    gas_estimate = contract_proxy.estimate_gas(check_block, "ret")
    assert gas_estimate, "Gas estimation should not fail here"
    startgas = safe_gas_limit(gas_estimate)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that it is assumed this runs fast enough so that the first transaction is not
    # mined before second is sent.
    contract_proxy.transact("ret", startgas)
    with pytest.raises(EthereumNonceTooLow):
        client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
        ).transact("ret", startgas)


def test_resending_mined_transaction_raises(deploy_client: JSONRPCClient) -> None:
    """ If a mined transaction is re-sent the exception `EthereumNonceTooLow` is raised. """
    # Use a _fixed_ gas price strategy so that both transactions are identical.
    deploy_client.web3.eth.setGasPriceStrategy(make_fixed_gas_price_strategy(GasPrice(2000000000)))
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    # Create a new instance of the JSONRPCClient, this will store the current available nonce
    client_invalid_nonce = JSONRPCClient(deploy_client.web3, deploy_client.privkey)

    check_block = deploy_client.get_checking_block()
    gas_estimate = contract_proxy.estimate_gas(check_block, "ret")
    assert gas_estimate, "Gas estimation should not fail here"
    startgas = safe_gas_limit(gas_estimate)

    txhash = contract_proxy.transact("ret", startgas)
    deploy_client.poll(txhash)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that the same function is called in this test.
    with pytest.raises(EthereumNonceTooLow):
        client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
        ).transact("ret", startgas)


def test_reusing_nonce_from_a_mined_transaction_raises(deploy_client: JSONRPCClient) -> None:
    """ If a _new_ transaction is sent with an old nonce the exception
    `EthereumNonceTooLow` is raised.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    # Create a new instance of the JSONRPCClient, this will store the current available nonce
    client_invalid_nonce = JSONRPCClient(deploy_client.web3, deploy_client.privkey)

    check_block = deploy_client.get_checking_block()
    txhash = contract_proxy.transact("ret", contract_proxy.estimate_gas(check_block, "ret"))

    # Wait for the transaction to be mined (concurrent transactions are tested
    # by test_local_transaction_with_zero_gasprice_is_mined)
    deploy_client.poll(txhash)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that a different function is called in this test.
    with pytest.raises(EthereumNonceTooLow):
        client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
        ).transact("ret_str", contract_proxy.estimate_gas(check_block, "ret_str"))


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


def test_resending_pending_transaction_with_lower_gas_raises(deploy_client: JSONRPCClient) -> None:
    """ If the same transaction is sent twice a JSON RPC error is raised. """
    # Use a _decreasing_ gas price strategy so that the second transactions is
    # lower than the first.
    deploy_client.web3.eth.setGasPriceStrategy(
        make_decreasing_gas_price_strategy(GasPrice(2000000000))
    )
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    client_invalid_nonce = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    check_block = deploy_client.get_checking_block()
    gas_estimate = contract_proxy.estimate_gas(check_block, "ret")
    assert gas_estimate, "Gas estimation should not fail here"
    startgas = safe_gas_limit(gas_estimate)

    contract_proxy.transact("ret", startgas)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that the same function is called in this test but the gas is decreasing.
    with pytest.raises(ReplacementTransactionUnderpriced):
        client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
        ).transact("ret", startgas)


def test_reusing_nonce_with_lower_gas_raises(deploy_client: JSONRPCClient) -> None:
    """ If a _new_ transaction is sent but with a lower gas the exception
    `ReplacementTransactionUnderpriced` is raised.
    """
    # Use a _decreasing_ gas price strategy so that the second transactions is
    # lower than the first.
    deploy_client.web3.eth.setGasPriceStrategy(
        make_decreasing_gas_price_strategy(GasPrice(2000000000))
    )
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.contract_address
    assert len(deploy_client.web3.eth.getCode(to_checksum_address(address))) > 0

    client_invalid_nonce = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    check_block = deploy_client.get_checking_block()
    gas_estimate = contract_proxy.estimate_gas(check_block, "ret")
    assert gas_estimate, "Gas estimation should not fail here"
    startgas = safe_gas_limit(gas_estimate)

    contract_proxy.transact("ret", startgas)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that the same function is called in this test but the gas is decreasing.
    with pytest.raises(ReplacementTransactionUnderpriced):
        client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.contract.abi, contract_address=contract_proxy.contract_address
        ).transact("ret_str", contract_proxy.estimate_gas(check_block, "ret_str"))
