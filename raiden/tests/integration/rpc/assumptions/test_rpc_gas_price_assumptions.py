from typing import Optional

import gevent
import pytest
from hexbytes import HexBytes
from web3 import HTTPProvider, Web3
from web3.exceptions import TransactionNotFound
from web3.types import TxReceipt

from raiden.constants import RECEIPT_FAILURE_CODE
from raiden.exceptions import EthereumNonceTooLow, ReplacementTransactionUnderpriced
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.eth_node import EthNodeDescription
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils.typing import Callable, Dict, GasPrice, List, PrivateKey


def make_fixed_gas_price_strategy(gas_price: GasPrice) -> Callable:
    def fixed_gas_price_strategy(_web3: Web3, _transaction_params: Dict) -> GasPrice:
        return gas_price

    return fixed_gas_price_strategy


def make_decreasing_gas_price_strategy(gas_price: GasPrice) -> Callable:
    # this is a really hacky way to create decreasing numbers
    def increasing_gas_price_strategy(web3: Web3, _transaction_params: Dict) -> GasPrice:
        old_counter = getattr(web3, "counter", gas_price)
        web3.counter = old_counter - 1  # type: ignore
        return old_counter

    return increasing_gas_price_strategy


def test_resending_pending_transaction_raises(deploy_client: JSONRPCClient) -> None:
    """If a pending transaction is re-sent the exception `EthereumNonceTooLow` is raised.

    This tests is only sufficient because of the companion test
    `test_resending_mined_transaction_raises` which shows that if the
    transaction has been mined a different exception is raised.
    """
    # Use a _fixed_ gas price strategy so that both transactions are identical.
    deploy_client.web3.eth.setGasPriceStrategy(make_fixed_gas_price_strategy(GasPrice(2000000000)))
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    # Create a new instance of the JSONRPCClient, this will store the current available nonce
    client_invalid_nonce = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "ret", {})
    assert estimated_transaction, "Gas estimation should not fail here"

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that it is assumed this runs fast enough so that the first transaction is not
    # mined before second is sent.
    deploy_client.transact(estimated_transaction)
    with pytest.raises(EthereumNonceTooLow):
        proxy_invalid = client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.abi, contract_address=contract_proxy.address
        )
        estimated_transaction_invalid = deploy_client.estimate_gas(proxy_invalid, "ret", {})
        msg = "ret always succed, gas estimation should have succeed."
        assert estimated_transaction_invalid, msg
        client_invalid_nonce.transact(estimated_transaction_invalid)


def test_resending_mined_transaction_raises(deploy_client: JSONRPCClient) -> None:
    """ If a mined transaction is re-sent the exception `EthereumNonceTooLow` is raised. """
    # Use a _fixed_ gas price strategy so that both transactions are identical.
    deploy_client.web3.eth.setGasPriceStrategy(make_fixed_gas_price_strategy(GasPrice(2000000000)))
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    # Create a new instance of the JSONRPCClient, this will store the current available nonce
    client_invalid_nonce = JSONRPCClient(deploy_client.web3, deploy_client.privkey)

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "ret", {})
    assert estimated_transaction, "Gas estimation should not fail here"

    transaction_hash = deploy_client.transact(estimated_transaction)
    deploy_client.poll_transaction(transaction_hash)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that the same function is called in this test.
    with pytest.raises(EthereumNonceTooLow):
        proxy_invalid = client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.abi, contract_address=contract_proxy.address
        )
        estimated_transaction_invalid = deploy_client.estimate_gas(proxy_invalid, "ret", {})
        msg = "ret always succed, gas estimation should have succeed."
        assert estimated_transaction_invalid, msg
        client_invalid_nonce.transact(estimated_transaction_invalid)


def test_reusing_nonce_from_a_mined_transaction_raises(deploy_client: JSONRPCClient) -> None:
    """If a _new_ transaction is sent with an old nonce the exception
    `EthereumNonceTooLow` is raised.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    # Create a new instance of the JSONRPCClient, this will store the current available nonce
    client_invalid_nonce = JSONRPCClient(deploy_client.web3, deploy_client.privkey)

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "ret", {})
    msg = "ret always succed, gas estimation should have succeed."
    assert estimated_transaction, msg
    transaction_hash = deploy_client.transact(estimated_transaction)

    # Wait for the transaction to be mined (concurrent transactions are tested
    # by test_local_transaction_with_zero_gasprice_is_mined)
    deploy_client.poll_transaction(transaction_hash)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that a different function is called in this test.
    with pytest.raises(EthereumNonceTooLow):
        proxy_invalid = client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.abi, contract_address=contract_proxy.address
        )
        estimated_transaction_invalid = deploy_client.estimate_gas(proxy_invalid, "ret_str", {})
        msg = "ret_str always succed, gas estimation should have succeed."
        assert estimated_transaction_invalid, msg
        client_invalid_nonce.transact(estimated_transaction_invalid)


def test_local_transaction_with_zero_gasprice_is_mined(deploy_client: JSONRPCClient) -> None:
    """If a transaction is sent through the eth_sendRawTransaction interface,
    directly to the miner, with a gas price of zero, it is considered local and
    mined anyways.
    """
    normal_gas_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    gas_price = GasPrice(0)
    gas_price_strategy = make_fixed_gas_price_strategy(gas_price)
    deploy_client.web3.eth.setGasPriceStrategy(gas_price_strategy)
    zero_gas_proxy = deploy_client.new_contract_proxy(
        abi=normal_gas_proxy.abi, contract_address=normal_gas_proxy.address
    )

    address = normal_gas_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    estimated_transaction = deploy_client.estimate_gas(zero_gas_proxy, "ret", {})
    assert estimated_transaction, "Gas estimation should not fail here"
    assert estimated_transaction.gas_price == 0, "Test requires a gas_price of zero"

    zerogas_transaction_sent = deploy_client.transact(estimated_transaction)
    zerogas_receipt = deploy_client.poll_transaction(zerogas_transaction_sent).receipt
    zerogas_tx = deploy_client.web3.eth.getTransaction(zerogas_transaction_sent.transaction_hash)

    msg = "Even thought the transaction had a zero gas price, it is not removed from the pool"
    assert zerogas_tx is not None, msg

    msg = "Even though the transaction had gas price of zero, it did get mined."
    assert zerogas_receipt["status"] != RECEIPT_FAILURE_CODE, msg


@pytest.mark.parametrize("blockchain_number_of_nodes", [2])
def test_remote_transaction_with_zero_gasprice_is_not_mined(
    web3: Web3, deploy_key: PrivateKey, eth_nodes_configuration: List[EthNodeDescription]
) -> None:
    """If the non-local transaction is sent with a gas price set to zero it is
    not mined.
    """
    host = "127.0.0.1"

    assert eth_nodes_configuration[0].miner
    miner_rpc_port = eth_nodes_configuration[0].rpc_port

    assert not eth_nodes_configuration[1].miner
    rpc_port = eth_nodes_configuration[1].rpc_port

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
        abi=normal_gas_proxy.abi, contract_address=normal_gas_proxy.address
    )

    address = normal_gas_proxy.address
    assert len(client.web3.eth.get_code(address)) > 0

    estimated_transaction = client.estimate_gas(zero_gas_proxy, "ret", {})
    assert estimated_transaction, "Gas estimation should not fail here"

    zerogas_transaction_sent = client.transact(estimated_transaction)

    # wait for how many blocks it took to mine the deployment, since this is a
    # private chain, if the new transaction will be mined it should be roughly
    # in the same time frame (adding two blocks to cover race conditions)
    target_block_number = client.block_number() + num_blocks_to_wait + 2
    while client.block_number() < target_block_number:
        gevent.sleep(0.5)

    miner_zerogas_receipt: Optional[TxReceipt]
    try:
        miner_zerogas_tx = miner_client.web3.eth.getTransaction(
            zerogas_transaction_sent.transaction_hash
        )
        miner_zerogas_receipt = miner_client.web3.eth.getTransactionReceipt(
            HexBytes(zerogas_transaction_sent.transaction_hash)
        )
    except TransactionNotFound:
        miner_zerogas_tx = None
        miner_zerogas_receipt = None

    msg = "The transaction was discarded by the miner, there is no transaction and no receipt"
    assert miner_zerogas_tx is None, msg
    assert miner_zerogas_receipt is None, msg

    zerogas_tx = client.web3.eth.getTransaction(zerogas_transaction_sent.transaction_hash)
    msg = (
        "The transaction was NOT discarded by the original node, because it is a local transaction"
    )
    assert zerogas_tx is not None, msg

    zerogas_receipt: Optional[TxReceipt]
    try:
        zerogas_receipt = client.web3.eth.getTransactionReceipt(
            HexBytes(zerogas_transaction_sent.transaction_hash)
        )
    except TransactionNotFound:
        zerogas_receipt = None

    msg = "The transaction receipt does NOT have a blockHash because the miner rejected it"
    assert zerogas_receipt is None or zerogas_receipt["blockHash"] is None, msg


def test_resending_pending_transaction_with_lower_gas_raises(deploy_client: JSONRPCClient) -> None:
    """ If the same transaction is sent twice a JSON RPC error is raised. """
    # Use a _decreasing_ gas price strategy so that the second transactions is
    # lower than the first.
    deploy_client.web3.eth.setGasPriceStrategy(
        make_decreasing_gas_price_strategy(GasPrice(2000000000))
    )
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    client_invalid_nonce = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "ret", {})
    assert estimated_transaction, "Gas estimation should not fail here"
    deploy_client.transact(estimated_transaction)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that the same function is called in this test but the gas is decreasing.
    with pytest.raises(ReplacementTransactionUnderpriced):
        proxy_invalid = client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.abi, contract_address=contract_proxy.address
        )
        estimated_transaction_invalid = client_invalid_nonce.estimate_gas(proxy_invalid, "ret", {})
        msg = "ret always succed, gas estimation should have succeed."
        assert estimated_transaction_invalid, msg
        client_invalid_nonce.transact(estimated_transaction_invalid)


def test_reusing_nonce_with_lower_gas_raises(deploy_client: JSONRPCClient) -> None:
    """If a _new_ transaction is sent but with a lower gas the exception
    `ReplacementTransactionUnderpriced` is raised.
    """
    # Use a _decreasing_ gas price strategy so that the second transactions is
    # lower than the first.
    deploy_client.web3.eth.setGasPriceStrategy(
        make_decreasing_gas_price_strategy(GasPrice(2000000000))
    )
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    client_invalid_nonce = JSONRPCClient(web3=deploy_client.web3, privkey=deploy_client.privkey)

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "ret", {})
    assert estimated_transaction, "Gas estimation should not fail here"
    deploy_client.transact(estimated_transaction)

    # At this point `client_invalid_nonce` has a nonce that is `1` too low,
    # since a transaction was sent using `deploy_client` above and these two
    # instances share the same underlying private key.
    #
    # Note that the same function is called in this test but the gas is decreasing.
    with pytest.raises(ReplacementTransactionUnderpriced):
        proxy_invalid = client_invalid_nonce.new_contract_proxy(
            abi=contract_proxy.abi, contract_address=contract_proxy.address
        )
        estimated_transaction = client_invalid_nonce.estimate_gas(proxy_invalid, "ret_str", {})
        assert estimated_transaction, "ret_str never fails, gas estimation must succeed."
        client_invalid_nonce.transact(estimated_transaction)
