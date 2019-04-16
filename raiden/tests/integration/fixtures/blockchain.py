import os

import pytest
from web3 import HTTPProvider, Web3

from raiden.constants import Environment, EthClient
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import DEVELOPMENT_CONTRACT_VERSION, RED_EYES_CONTRACT_VERSION
from raiden.tests.utils.eth_node import (
    EthNodeDescription,
    GenesisDescription,
    run_private_blockchain,
)
from raiden.tests.utils.network import jsonrpc_services
from raiden.tests.utils.tests import cleanup_tasks
from raiden.utils import privatekey_to_address
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals

_ETH_LOGDIR = os.environ.get('RAIDEN_TESTS_ETH_LOGSDIR')


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
        blockchain_extra_config,
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

    if blockchain_type not in {client.value for client in EthClient}:
        raise ValueError(f'unknown blockchain_type {blockchain_type}')

    host = '127.0.0.1'
    rpc_port = blockchain_rpc_ports[0]
    endpoint = f'http://{host}:{rpc_port}'
    web3 = Web3(HTTPProvider(endpoint))

    assert len(blockchain_private_keys) == len(blockchain_rpc_ports)
    assert len(blockchain_private_keys) == len(blockchain_p2p_ports)

    eth_nodes = [
        EthNodeDescription(
            private_key=key,
            rpc_port=rpc,
            p2p_port=p2p,
            miner=(pos == 0),
            extra_config=blockchain_extra_config,
            blockchain_type=blockchain_type,
        )
        for pos, (key, rpc, p2p) in enumerate(
            zip(
                blockchain_private_keys,
                blockchain_rpc_ports,
                blockchain_p2p_ports,
            ),
        )
    ]

    accounts_to_fund = [
        privatekey_to_address(key)
        for key in keys_to_fund
    ]

    base_datadir = str(tmpdir)

    if _ETH_LOGDIR:
        base_logdir = os.path.join(_ETH_LOGDIR, blockchain_type, request.node.name)
    else:
        base_logdir = os.path.join(base_datadir, 'logs')

    genesis_description = GenesisDescription(
        prefunded_accounts=accounts_to_fund,
        chain_id=chain_id,
        random_marker=random_marker,
    )
    eth_node_runner = run_private_blockchain(
        web3=web3,
        eth_nodes=eth_nodes,
        base_datadir=base_datadir,
        log_dir=base_logdir,
        verbosity='info',
        genesis_description=genesis_description,
    )
    with eth_node_runner:
        yield web3

    cleanup_tasks()


@pytest.fixture
def deploy_client(blockchain_rpc_ports, deploy_key, web3, blockchain_type):
    if blockchain_type == 'parity':
        return JSONRPCClient(web3, deploy_key, gas_estimate_correction=lambda gas: 2 * gas)
    return JSONRPCClient(web3, deploy_key)


@pytest.fixture
def contracts_path(environment_type):
    version = RED_EYES_CONTRACT_VERSION
    if environment_type == Environment.DEVELOPMENT:
        version = DEVELOPMENT_CONTRACT_VERSION

    return contracts_precompiled_path(version)


@pytest.fixture
def contract_manager(contracts_path):
    return ContractManager(contracts_path)


@pytest.fixture
def deploy_service(deploy_key, deploy_client, contract_manager):
    return BlockChainService(
        jsonrpc_client=deploy_client,
        contract_manager=contract_manager,
    )


@pytest.fixture
def blockchain_services(
        deploy_service,
        private_keys,
        secret_registry_address,
        service_registry_address,
        token_network_registry_address,
        web3,
        contract_manager,
):
    return jsonrpc_services(
        deploy_service=deploy_service,
        private_keys=private_keys,
        secret_registry_address=secret_registry_address,
        service_registry_address=service_registry_address,
        token_network_registry_address=token_network_registry_address,
        web3=web3,
        contract_manager=contract_manager,
    )
