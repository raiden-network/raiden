import pytest
from eth_utils import to_canonical_address

from raiden.constants import BLOCK_ID_LATEST, TRANSACTION_INTRINSIC_GAS
from raiden.exceptions import InsufficientEth
from raiden.network.rpc.client import (
    JSONRPCClient,
    SmartContractCall,
    TransactionEstimated,
    discover_next_available_nonce,
    gas_price_for_fast_transaction,
    was_transaction_successfully_mined,
)
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils.formatting import to_checksum_address
from raiden.utils.smart_contracts import safe_gas_limit
from raiden.utils.typing import BlockHash, Nonce


def test_transact_opcode(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that did not throw is 0x1 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "ret", {})
    assert estimated_transaction
    estimated_transaction.estimated_gas *= 2

    transaction_sent = deploy_client.transact(estimated_transaction)
    transaction_mined = deploy_client.poll_transaction(transaction_sent)
    assert was_transaction_successfully_mined(transaction_mined), "Transaction must be succesfull"


def test_transact_throws_opcode(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that hit an assert or require is 0x0 """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = to_canonical_address(contract_proxy.address)
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    # the method always fails, so the gas estimation returns 0 here, using a
    # hardcoded a value to circumvent gas estimation.
    estimated_gas = safe_gas_limit(22000)
    gas_price = gas_price_for_fast_transaction(deploy_client.web3)

    block = deploy_client.get_block(BLOCK_ID_LATEST)

    estimated_transaction_fail_assert = TransactionEstimated(
        from_address=address,
        data=SmartContractCall(contract_proxy, "fail_assert", (), {}, value=0),
        eth_node=deploy_client.eth_node,
        extra_log_details={},
        estimated_gas=estimated_gas,
        gas_price=gas_price,
        approximate_block=(BlockHash(block["hash"]), block["number"]),
    )
    transaction_fail_assert_sent = deploy_client.transact(estimated_transaction_fail_assert)
    transaction_fail_assert_mined = deploy_client.poll_transaction(transaction_fail_assert_sent)
    msg = "Transaction must have failed"
    assert not was_transaction_successfully_mined(transaction_fail_assert_mined), msg

    estimated_transaction_fail_require = TransactionEstimated(
        from_address=address,
        data=SmartContractCall(contract_proxy, "fail_require", (), {}, value=0),
        eth_node=deploy_client.eth_node,
        extra_log_details={},
        estimated_gas=estimated_gas,
        gas_price=gas_price,
        approximate_block=(BlockHash(block["hash"]), block["number"]),
    )
    transaction_fail_require_sent = deploy_client.transact(estimated_transaction_fail_require)
    transaction_fail_require_mined = deploy_client.poll_transaction(transaction_fail_require_sent)
    msg = "Transaction must have failed"
    assert not was_transaction_successfully_mined(transaction_fail_require_mined), msg


def test_transact_opcode_oog(deploy_client: JSONRPCClient) -> None:
    """ The receipt status field of a transaction that did NOT throw is 0x0. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    address = contract_proxy.address
    assert len(deploy_client.web3.eth.get_code(address)) > 0

    # divide the estimate by 2 to run into out-of-gas
    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "loop", {}, 1000)
    assert estimated_transaction
    estimated_transaction.estimated_gas //= 2

    transaction_sent = deploy_client.transact(estimated_transaction)
    transaction_mined = deploy_client.poll_transaction(transaction_sent)
    msg = "Transaction must be succesfull"
    assert not was_transaction_successfully_mined(transaction_mined), msg


def test_transact_fails_if_the_account_does_not_have_enough_eth_to_pay_for_the_gas(
    deploy_client: JSONRPCClient,
) -> None:
    """The gas estimation does not fail if the transaction execution requires
    more gas then the account's eth balance. However sending the transaction
    will.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcTest")

    estimated_transaction = deploy_client.estimate_gas(contract_proxy, "loop", {}, 1000)
    assert estimated_transaction, "The gas estimation should not have failed."

    burn_eth(deploy_client, amount_to_leave=estimated_transaction.estimated_gas // 2)
    with pytest.raises(InsufficientEth):
        deploy_client.transact(estimated_transaction)


def test_discover_next_available_nonce(deploy_client: JSONRPCClient) -> None:
    """`parity_discover_next_available_nonce` returns the *next available nonce*.

    Notes:
    - This is not the same as the *highest unused nonce*, additional details on
      issue #4976.
    - The behaviour of `geth_discover_next_available_nonce` and
      `parity_discover_next_available_nonce` should match.
    """
    web3 = deploy_client.web3
    random_address = make_address()
    gas_price = web3.eth.gas_price  # pylint: disable=no-member
    eth_node = deploy_client.eth_node
    next_nonce = discover_next_available_nonce(web3, eth_node, deploy_client.address)

    # Should be larger than the number of transactions that can fit in a single
    # block, to ensure all transactions from the pool are accounted for.
    QTY_TRANSACTIONS = 1000

    # Test the next available nonce
    for _ in range(QTY_TRANSACTIONS):
        transaction = {
            "to": to_checksum_address(random_address),
            "gas": TRANSACTION_INTRINSIC_GAS,
            "nonce": next_nonce,
            "value": 1,
            "gasPrice": gas_price,
            "chainId": deploy_client.chain_id,
        }
        signed_txn = deploy_client.web3.eth.account.sign_transaction(
            transaction, deploy_client.privkey
        )
        deploy_client.web3.eth.send_raw_transaction(signed_txn.rawTransaction)

        next_nonce = Nonce(next_nonce + 1)
        msg = "The nonce must increment when a new transaction is sent."
        assert (
            discover_next_available_nonce(web3, eth_node, deploy_client.address) == next_nonce
        ), msg

    skip_nonce = next_nonce + 1

    # Test the next available nonce is not the same as the highest unused
    # nonce.
    for _ in range(QTY_TRANSACTIONS):
        transaction = {
            "to": to_checksum_address(random_address),
            "gas": TRANSACTION_INTRINSIC_GAS,
            "nonce": skip_nonce,
            "value": 1,
            "gasPrice": gas_price,
            "chainId": deploy_client.chain_id,
        }
        signed_txn = deploy_client.web3.eth.account.sign_transaction(
            transaction, deploy_client.privkey
        )
        deploy_client.web3.eth.send_raw_transaction(signed_txn.rawTransaction)

        available_nonce = discover_next_available_nonce(web3, eth_node, deploy_client.address)

        msg = "Expected the latest unused nonce."
        assert available_nonce == next_nonce, msg
        assert available_nonce != skip_nonce, msg

        skip_nonce = Nonce(skip_nonce + 1)
