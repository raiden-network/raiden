import gevent
import pytest
import rlp
from eth_utils import keccak, to_canonical_address
from web3 import Web3
from web3.exceptions import TransactionNotFound

from raiden.network.rpc.client import discover_next_available_nonce, is_supported_client
from raiden.tests.utils.smartcontracts import compile_test_smart_contract
from raiden.utils.keys import privatekey_to_address
from raiden.utils.typing import Nonce


@pytest.mark.skip(
    "Failure of this test does not imply in a bug. The test exists to exercise "
    "an assumption and to show that a corner case is possible."
)
def test_events_can_happen_in_the_deployment_block(web3: Web3, deploy_key: bytes) -> None:
    """It is possible to send transactions to a smart contract that has not
    been mined yet, resulting in events being emitted in the same block the
    smart contract was deployed.
    """
    address = privatekey_to_address(deploy_key)

    contract_name = "RpcTest"
    contracts, contract_key = compile_test_smart_contract(contract_name)
    contract = contracts[contract_key]

    _, eth_node, _ = is_supported_client(web3.clientVersion)
    assert eth_node, "unknown eth_node."
    nonce = discover_next_available_nonce(web3, eth_node, address)

    retries = 5

    for _ in range(retries):
        contract_address = to_canonical_address(keccak(rlp.encode([address, nonce]))[:20])
        contract_object = web3.eth.contract(
            address=contract_address, abi=contract["abi"], bytecode=contract["bin"]
        )

        deploy_transaction_data = contract_object.constructor().buildTransaction()
        call_transaction_data = contract_object.functions.createEvent(1).buildTransaction()

        deploy_transaction_data["nonce"] = nonce
        nonce = Nonce(nonce + 1)
        call_transaction_data["nonce"] = nonce
        nonce = Nonce(nonce + 1)

        deploy_signed_txn = web3.eth.account.sign_transaction(deploy_transaction_data, deploy_key)
        call_signed_txn = web3.eth.account.sign_transaction(call_transaction_data, deploy_key)

        deploy_tx_hash = web3.eth.send_raw_transaction(deploy_signed_txn.rawTransaction)
        call_tx_hash = web3.eth.send_raw_transaction(call_signed_txn.rawTransaction)

        while True:
            try:
                deploy_tx_receipt = web3.eth.getTransactionReceipt(deploy_tx_hash)
                call_tx_receipt = web3.eth.getTransactionReceipt(call_tx_hash)

                # This is the condition this test is trying to hit, when both
                # the deployment of the transaction and it's first call happen
                # in the same block. As a consequence, because this can happen
                # in at least one Ethereum implementation (e.g. Geth 1.9.15),
                # all filters *must* start in the same block as the smart
                # contract deployment block.
                if deploy_tx_receipt["blockHash"] == call_tx_receipt["blockHash"]:
                    return

                break

            except TransactionNotFound:
                gevent.sleep(1.0)

    assert False, f"None of the {retries} transactions got mined in the same block."
