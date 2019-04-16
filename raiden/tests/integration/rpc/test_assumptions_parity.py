import pytest

from raiden.tests.integration.rpc.test_assumptions import deploy_rpc_test_contract
from raiden.utils import safe_gas_limit

pytestmark = pytest.mark.usefixtures('skip_if_not_parity')

# set very low values to force the client to prune old state
STATE_PRUNNING = {
    'pruning': 'fast',
    'pruning-history': 1,
    'pruning-memory': 1,
    'cache-size-db': 1,
    'cache-size-blocks': 1,
    'cache-size-queue': 1,
    'cache-size': 1,
}


@pytest.mark.parametrize('blockchain_extra_config', [STATE_PRUNNING])
def test_parity_request_prunned_data_raises_an_exception(deploy_client):
    """ Interacting with an old block identifier with a pruning client throws. """
    contract_proxy = deploy_rpc_test_contract(deploy_client, 'RpcWithStorageTest')
    iterations = 1000

    def send_transaction():
        check_block = deploy_client.get_checking_block()
        startgas = contract_proxy.estimate_gas(check_block, 'waste_storage', iterations)
        startgas = safe_gas_limit(startgas)
        transaction = contract_proxy.transact('waste_storage', startgas, iterations)
        deploy_client.poll(transaction)
        return deploy_client.get_transaction_receipt(transaction)

    first_receipt = send_transaction()
    pruned_block_number = first_receipt['blockNumber']

    for _ in range(10):
        send_transaction()

    with pytest.raises(ValueError):
        contract_proxy.contract.functions.const().call(block_identifier=pruned_block_number)

    with pytest.raises(ValueError):
        contract_proxy.contract.functions.get(1).call(block_identifier=pruned_block_number)
