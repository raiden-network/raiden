import pytest
from eth_utils import to_canonical_address

from raiden.network.rpc.client import JSONRPCClient, TransactionMined, check_address_has_code
from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract

pytestmark = pytest.mark.usefixtures("skip_if_not_parity")

# set very low values to force the client to prune old state
STATE_PRUNING = {
    "pruning": "fast",
    "pruning-history": 1,
    "pruning-memory": 1,
    "cache-size-db": 1,
    "cache-size-blocks": 1,
    "cache-size-queue": 1,
    "cache-size": 1,
}


@pytest.mark.parametrize("blockchain_extra_config", [STATE_PRUNING])
def test_parity_request_pruned_data_raises_an_exception(deploy_client: JSONRPCClient) -> None:
    """ Interacting with an old block identifier with a pruning client throws. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")
    iterations = 1000

    def send_transaction() -> TransactionMined:
        estimated_transaction = deploy_client.estimate_gas(
            contract_proxy, "waste_storage", {}, iterations
        )
        assert estimated_transaction
        transaction = deploy_client.transact(estimated_transaction)
        return deploy_client.poll_transaction(transaction)

    first_receipt = send_transaction().receipt
    pruned_block_number = first_receipt["blockNumber"]

    for _ in range(10):
        send_transaction()

    with pytest.raises(ValueError):
        contract_proxy.functions.const().call(block_identifier=pruned_block_number)

    with pytest.raises(ValueError):
        contract_proxy.functions.get(1).call(block_identifier=pruned_block_number)

    with pytest.raises(ValueError):
        check_address_has_code(
            deploy_client,
            to_canonical_address(contract_proxy.address),
            "RpcWithStorageTest",
            given_block_identifier=pruned_block_number,
        )


@pytest.mark.parametrize("blockchain_extra_config", [STATE_PRUNING])
def test_parity_request_block_data_does_not_raise_an_exception(
    deploy_client: JSONRPCClient,
) -> None:
    """Interacting with a pruned block through eth_getBlock does not raise.

    If this assumptions tests fails the `BlockchainEvents` has to be fixed.
    Currently it assumes that it can fetch metadata about any block, namely the
    block number / hash / gas limit.
    """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")
    iterations = 1000

    def send_transaction() -> TransactionMined:
        estimated_transaction = deploy_client.estimate_gas(
            contract_proxy, "waste_storage", {}, iterations
        )
        assert estimated_transaction
        transaction = deploy_client.transact(estimated_transaction)
        return deploy_client.poll_transaction(transaction)

    first_receipt = send_transaction().receipt
    pruned_block_number = first_receipt["blockNumber"]

    for _ in range(10):
        send_transaction()

    # Make sure pruning happened, otherwise the test below is not useful.
    with pytest.raises(ValueError):
        contract_proxy.functions.const().call(block_identifier=pruned_block_number)

    latest_confirmed_block = deploy_client.web3.eth.get_block(pruned_block_number)

    msg = (
        "getBlock did not return the expected metadata for a pruned block "
        "`BlockchainEvents` code has to be adjusted"
    )
    assert latest_confirmed_block["hash"], msg
    assert latest_confirmed_block["gasLimit"], msg
