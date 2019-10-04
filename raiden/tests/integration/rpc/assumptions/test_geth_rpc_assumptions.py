import gevent
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
        contract_proxy.contract.functions.const().call(block_identifier=pruned_block_number)

    with pytest.raises(ValueError):
        contract_proxy.contract.functions.get(1).call(block_identifier=pruned_block_number)
