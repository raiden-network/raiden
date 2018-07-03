import os
import pytest

from raiden.tests.utils.smoketest import (
    load_smoketest_config,
    start_ethereum,
)


@pytest.fixture(scope='session')
def blockchain_provider():
    print("fixture init")
    smoketest_config = load_smoketest_config()
    ethereum, ethereum_config = start_ethereum(smoketest_config['genesis'])
    discovery_contract_address = smoketest_config['contracts']['discovery_address']
    registry_contract_address = smoketest_config['contracts']['registry_address']
    eth_rpc_endpoint = 'http://127.0.0.1:{}'.format(ethereum_config['rpc'])
    keystore_path = ethereum_config['keystore']
    datadir_path = os.path.split(keystore_path)[0]
    network_id = '627'
    password_file_path = os.path.join(keystore_path, 'password')
    with open(password_file_path, 'w') as handler:
        handler.write('password')
    return {'ethereum': ethereum,
            'ethereum_config': ethereum_config,
            'discovery_contract_address': discovery_contract_address,
            'registry_contract_address': registry_contract_address,
            'eth_rpc_endpoint': eth_rpc_endpoint,
            'keystore_path': keystore_path,
            'datadir_path': datadir_path,
            'password_file_path': password_file_path,
            'network_id': network_id}
