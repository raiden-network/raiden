import pytest

from raiden.tests.utils.smartcontracts import deploy_rpc_test_contract
from raiden.utils import safe_gas_limit

pytestmark = pytest.mark.usefixtures("skip_if_not_geth")


def test_geth_request_pruned_data_raises_an_exception(deploy_client, web3):
    """ Interacting with an old block identifier with a pruning client throws. """
    contract_proxy, _ = deploy_rpc_test_contract(deploy_client, "RpcWithStorageTest")
    iterations = 1

    def send_transaction():
        check_block = deploy_client.get_checking_block()
        startgas = contract_proxy.estimate_gas(check_block, "waste_storage", iterations)
        startgas = safe_gas_limit(startgas)
        transaction = contract_proxy.transact("waste_storage", startgas, iterations)
        deploy_client.poll(transaction)
        return deploy_client.get_transaction_receipt(transaction)

    first_receipt = send_transaction()
    pruned_block_number = first_receipt["blockNumber"]

    # geth keeps the latest 128 blocks before pruning. Unfortunately, this can
    # not be configured to speed this test up.
    non_pruned_blocks = 128
    while web3.eth.blockNumber < pruned_block_number + non_pruned_blocks + 1:
        send_transaction()

    with pytest.raises(ValueError):
        contract_proxy.contract.functions.const().call(block_identifier=pruned_block_number)

    with pytest.raises(ValueError):
        contract_proxy.contract.functions.get(1).call(block_identifier=pruned_block_number)
