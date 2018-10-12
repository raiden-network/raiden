import pytest
from web3 import HTTPProvider, Web3

from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.geth import GethNodeDescription, geth_run_private_blockchain
from raiden.tests.utils.network import jsonrpc_services
from raiden.tests.utils.tests import cleanup_tasks
from raiden.utils import privatekey_to_address
from raiden_contracts.contract_manager import (
    ContractManager,
    contracts_deployed_path,
    contracts_precompiled_path,
)

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


@pytest.fixture
def endpoint_discovery_services(blockchain_services, endpoint_registry_address):
    return [
        ContractDiscovery(chain.node_address, chain.discovery(endpoint_registry_address))
        for chain in blockchain_services.blockchain_services
    ]


@pytest.fixture
def web3(
        blockchain_p2p_ports,
        blockchain_private_keys,
        blockchain_rpc_ports,
        blockchain_type,
        deploy_key,
        private_keys,
        random_marker,
        request,
        tmpdir,
        chain_id,
):
    """ Starts a private chain with accounts funded. """
    # include the deploy key in the list of funded accounts
    keys_to_fund = set(private_keys)
    keys_to_fund.add(deploy_key)
    keys_to_fund = sorted(keys_to_fund)

    if blockchain_type == 'geth':
        host = '0.0.0.0'
        rpc_port = blockchain_rpc_ports[0]
        endpoint = f'http://{host}:{rpc_port}'
        web3 = Web3(HTTPProvider(endpoint))

        assert len(blockchain_private_keys) == len(blockchain_rpc_ports)
        assert len(blockchain_private_keys) == len(blockchain_p2p_ports)

        geth_nodes = [
            GethNodeDescription(
                key,
                rpc,
                p2p,
                miner=(pos == 0),
            )
            for pos, (key, rpc, p2p) in enumerate(zip(
                blockchain_private_keys,
                blockchain_rpc_ports,
                blockchain_p2p_ports,
            ))
        ]

        accounts_to_fund = [
            privatekey_to_address(key)
            for key in keys_to_fund
        ]

        geth_processes = geth_run_private_blockchain(
            web3,
            accounts_to_fund,
            geth_nodes,
            str(tmpdir),
            chain_id,
            request.config.option.verbose,
            random_marker,
        )

        yield web3

        for process in geth_processes:
            process.terminate()

        cleanup_tasks()

    else:
        raise ValueError(f'unknown blockchain_type {blockchain_type}')


@pytest.fixture
def deploy_client(blockchain_rpc_ports, deploy_key, web3):
    return JSONRPCClient(web3, deploy_key)


@pytest.fixture
def testing_network_id():
    return 1


@pytest.fixture
def testing_contracts_version():
    return None


@pytest.fixture
def contract_manager(testing_network_id, testing_contracts_version):
    # Keeping this only for documentation purposes if we want to test specific
    # contract versions apart from the last one
    if False:
        contracts_path = contracts_deployed_path(testing_network_id, testing_contracts_version)
    else:
        contracts_path = contracts_precompiled_path()
    return ContractManager(contracts_path)


@pytest.fixture
def deploy_service(deploy_key, deploy_client, contract_manager):
    return BlockChainService(
        privatekey_bin=deploy_key,
        jsonrpc_client=deploy_client,
        contract_manager=contract_manager,
    )


@pytest.fixture
def blockchain_services(
        deploy_service,
        private_keys,
        secret_registry_address,
        token_network_registry_address,
        web3,
        contract_manager,
):
    return jsonrpc_services(
        deploy_service,
        private_keys,
        secret_registry_address,
        token_network_registry_address,
        web3=web3,
        contract_manager=contract_manager,
    )
