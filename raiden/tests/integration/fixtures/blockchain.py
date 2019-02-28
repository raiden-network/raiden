import os

import pytest
from web3 import HTTPProvider, Web3

from raiden.constants import Environment
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import (
    DEVELOPMENT_CONTRACT_VERSION,
    RED_EYES_CONTRACT_VERSION,
    SUPPORTED_ETH_CLIENTS,
)
from raiden.tests.utils.eth_node import EthNodeDescription, run_private_blockchain
from raiden.tests.utils.network import jsonrpc_services
from raiden.tests.utils.tests import cleanup_tasks
from raiden.utils import privatekey_to_address
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals

_GETH_LOGDIR = os.environ.get('RAIDEN_TESTS_GETH_LOGSDIR')


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

    if blockchain_type not in SUPPORTED_ETH_CLIENTS:
        raise ValueError(f'unknown blockchain_type {blockchain_type}')

    host = '0.0.0.0'
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
            blockchain_type=blockchain_type,
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

    base_datadir = str(tmpdir)

    if _GETH_LOGDIR:
        base_logdir = os.path.join(_GETH_LOGDIR, request.node.name)
    else:
        base_logdir = os.path.join(base_datadir, 'logs')

    geth_processes = run_private_blockchain(
        web3=web3,
        accounts_to_fund=accounts_to_fund,
        eth_nodes=eth_nodes,
        base_datadir=base_datadir,
        log_dir=base_logdir,
        chain_id=chain_id,
        verbosity=request.config.option.verbose,
        random_marker=random_marker,
    )

    yield web3

    for process in geth_processes:
        process.terminate()

    cleanup_tasks()


@pytest.fixture
def deploy_client(blockchain_rpc_ports, deploy_key, web3, blockchain_type):
    if blockchain_type == 'parity':
        return JSONRPCClient(web3, deploy_key, gas_estimate_correction=lambda gas: 2 * gas)
    return JSONRPCClient(web3, deploy_key)


@pytest.fixture
def contract_manager(environment_type):
    version = RED_EYES_CONTRACT_VERSION
    if environment_type == Environment.DEVELOPMENT:
        version = DEVELOPMENT_CONTRACT_VERSION

    return ContractManager(contracts_precompiled_path(version))


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
