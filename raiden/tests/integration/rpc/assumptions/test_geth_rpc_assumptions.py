import gevent
import pytest
from web3 import Web3

from raiden.network.rpc.client import (
    EthTransfer,
    JSONRPCClient,
    TransactionMined,
    gas_price_for_fast_transaction,
    geth_discover_next_available_nonce,
)
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils.typing import Address

pytestmark = pytest.mark.usefixtures("skip_if_not_geth")


def test_geth_request_pruned_data_raises_an_exception(
    deploy_client: JSONRPCClient, web3: Web3
) -> None:
    """ Interacting with an old block identifier with a pruning client throws. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")
    iterations = 1

    def send_transaction() -> TransactionMined:
        estimated_transaction = deploy_client.estimate_gas(
            contract_proxy, "waste_storage", {}, iterations
        )
        assert estimated_transaction
        transaction_hash = deploy_client.transact(estimated_transaction)
        return deploy_client.poll_transaction(transaction_hash)

    first_receipt = send_transaction().receipt
    mined_block_number = first_receipt["blockNumber"]

    while mined_block_number + 127 > web3.eth.blockNumber:
        gevent.sleep(0.5)

    # geth keeps the latest 128 blocks before pruning. Unfortunately, this can
    # not be configured to speed this test up.
    # According to the geth devs if we run a PoA chain (clique, dev mode) and
    # HEAD-127 doesn't contain any transactions, then the state of HEAD-127 will
    # be the same as HEAD-128, so it will still be referenced and not deleted.
    # So for this test we mine a transaction, wait for mined + 127 block and then
    # query the previous block which should be pruned

    pruned_block_number = mined_block_number - 1
    with pytest.raises(ValueError):
        contract_proxy.functions.const().call(block_identifier=pruned_block_number)

    with pytest.raises(ValueError):
        contract_proxy.functions.get(1).call(block_identifier=pruned_block_number)


def test_geth_discover_next_available_nonce_concurrent_transactions(
    deploy_client: JSONRPCClient, skip_if_parity: bool  # pylint: disable=unused-argument
) -> None:
    """ Test that geth_discover_next_available nonce works correctly

    Reproduced the problem seen here:
    https://github.com/raiden-network/raiden/pull/3683#issue-264551799
    """

    def send_transaction(to: Address) -> None:
        deploy_client.transact(
            EthTransfer(
                to_address=to,
                value=0,
                gas_price=gas_price_for_fast_transaction(deploy_client.web3),
            )
        )

    greenlets = {gevent.spawn(send_transaction, to=make_address()) for _ in range(100)}
    gevent.joinall(set(greenlets), raise_error=True)

    nonce = geth_discover_next_available_nonce(
        web3=deploy_client.web3, address=deploy_client.address
    )
    msg = "The nonce must increase exactly once per transaciton."
    assert nonce == 100, msg
    assert nonce == deploy_client._available_nonce, msg
