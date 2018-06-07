# -*- coding: utf-8 -*-
from collections import namedtuple

import pytest
import structlog
from eth_utils import decode_hex

from raiden.utils import (
    get_contract_path,
    privatekey_to_address,
)
from raiden.tests.utils.tests import cleanup_tasks
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.blockchain import geth_create_blockchain
from raiden.settings import GAS_PRICE
from raiden.utils.solc import compile_files_cwd

BlockchainServices = namedtuple(
    'BlockchainServices',
    (
        'deploy_registry',
        'deploy_service',
        'blockchain_services',
    )
)
log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


def _token_addresses(
        token_amount,
        number_of_tokens,
        deploy_service,
        registry,
        participants,
        register
):
    """ Deploy `number_of_tokens` ERC20 token instances with `token_amount` minted and
    distributed among `blockchain_services`. Optionally the instances will be registered with
    the raiden registry.
    Args:
        token_amount (int): number of units that will be created per token
        number_of_tokens (int): number of token instances that will be created
        deploy_service (BlockchainService): the blockchain connection that will deploy
        participants (list(address)): participant addresses that will receive tokens
        register (bool): switch to control registration with the raiden Registry contract
    """
    result = list()
    for _ in range(number_of_tokens):
        if register:
            token_address = deploy_service.deploy_and_register_token(
                registry,
                contract_name='HumanStandardToken',
                contract_path=get_contract_path('HumanStandardToken.sol'),
                constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
            )
            result.append(token_address)
        else:
            token_address = deploy_service.deploy_contract(
                contract_name='HumanStandardToken',
                contract_path=get_contract_path('HumanStandardToken.sol'),
                constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
            )
            result.append(token_address)

        # only the creator of the token starts with a balance (deploy_service),
        # transfer from the creator to the other nodes
        for transfer_to in participants:
            deploy_service.token(token_address).transfer(
                transfer_to,
                token_amount // len(participants),
            )

    return result


@pytest.fixture
def register_tokens():
    """ Should fixture generated tokens be registered with raiden (default: True). """
    return True


@pytest.fixture
def token_addresses(
        request,
        token_amount,
        number_of_tokens,
        blockchain_services,
        register_tokens
):
    """ Fixture that yields `number_of_tokens` ERC20 token addresses, where the
    `token_amount` (per token) is distributed among the addresses behind `blockchain_services` and
    potentially pre-registered with the raiden Registry.
    The following arguments can control the behavior:

    Args:
        token_amount (int): the overall number of units minted per token
        number_of_tokens (int): the number of token instances
        register_tokens (bool): controls if tokens will be registered with raiden Registry
    """

    participants = [
        privatekey_to_address(blockchain_service.private_key) for
        blockchain_service in blockchain_services.blockchain_services
    ]
    token_addresses = _token_addresses(
        token_amount,
        number_of_tokens,
        blockchain_services.deploy_service,
        blockchain_services.deploy_registry,
        participants,
        register_tokens
    )

    return token_addresses


@pytest.fixture
def blockchain_services(
        request,
        deploy_key,
        deploy_client,
        private_keys,
        poll_timeout,
        blockchain_backend,  # This fixture is required because it will start
                             # the geth subprocesses
        blockchain_rpc_ports,
        blockchain_type,
):

    registry_address = None

    if blockchain_type == 'geth':
        return _jsonrpc_services(
            deploy_key,
            deploy_client,
            private_keys,
            request.config.option.verbose,
            poll_timeout,
            registry_address,  # _jsonrpc_services will handle the None value
        )

    raise ValueError('unknown cluster type {}'.format(blockchain_type))


@pytest.fixture
def endpoint_discovery_services(blockchain_services):
    discovery_address = blockchain_services.deploy_service.deploy_contract(
        'EndpointRegistry',
        get_contract_path('EndpointRegistry.sol'),
    )

    return [
        ContractDiscovery(chain.node_address, chain.discovery(discovery_address))
        for chain in blockchain_services.blockchain_services
    ]


@pytest.fixture
def blockchain_backend(
        request,
        deploy_key,
        deploy_client,
        private_keys,
        blockchain_private_keys,
        blockchain_p2p_ports,
        blockchain_rpc_ports,
        tmpdir,
        random_marker,
        blockchain_type,
):

    genesis_path = None

    if blockchain_type == 'geth':
        return _geth_blockchain(
            request,
            deploy_key,
            deploy_client,
            private_keys,
            blockchain_private_keys,
            blockchain_p2p_ports,
            blockchain_rpc_ports,
            tmpdir,
            random_marker,
            genesis_path,
        )

    # check pytest_addoption
    raise ValueError('unknow cluster type {}'.format(blockchain_type))


@pytest.fixture
def deploy_client(blockchain_type, blockchain_rpc_ports, deploy_key):
    if blockchain_type == 'geth':
        host = '0.0.0.0'
        rpc_port = blockchain_rpc_ports[0]

        deploy_client = JSONRPCClient(
            host,
            rpc_port,
            deploy_key,
        )

        return deploy_client

    raise ValueError('unknow cluster type {}'.format(blockchain_type))


def _geth_blockchain(
        request,
        deploy_key,
        deploy_client,
        private_keys,
        blockchain_private_keys,
        blockchain_p2p_ports,
        blockchain_rpc_ports,
        tmpdir,
        random_marker,
        genesis_path):

    """ Helper to do proper cleanup. """
    geth_processes = geth_create_blockchain(
        deploy_key,
        deploy_client,
        private_keys,
        blockchain_private_keys,
        blockchain_rpc_ports,
        blockchain_p2p_ports,
        str(tmpdir),
        request.config.option.verbose,
        random_marker,
        genesis_path,
    )

    def _cleanup():
        for process in geth_processes:
            process.terminate()

        cleanup_tasks()

    request.addfinalizer(_cleanup)
    return geth_processes


def _jsonrpc_services(
        deploy_key,
        deploy_client,
        private_keys,
        verbose,
        poll_timeout,
        registry_address=None
):
    # we cannot instantiate BlockChainService without a registry, so first
    # deploy it directly with a JSONRPCClient
    if registry_address is None:
        registry_path = get_contract_path('Registry.sol')
        registry_contracts = compile_files_cwd([registry_path])

        log.info('Deploying registry contract')
        registry_proxy = deploy_client.deploy_solidity_contract(
            'Registry',
            registry_contracts,
            dict(),
            tuple(),
            contract_path=registry_path,
            timeout=poll_timeout,
        )
        registry_address = decode_hex(registry_proxy.contract.address)

    # at this point the blockchain must be running, this will overwrite the
    # method so even if the client is patched twice, it should work fine

    deploy_blockchain = BlockChainService(
        deploy_key,
        deploy_client,
        GAS_PRICE,
    )
    deploy_registry = deploy_blockchain.registry(registry_address)

    host = '0.0.0.0'
    blockchain_services = list()
    for privkey in private_keys:
        rpc_client = JSONRPCClient(
            host,
            deploy_client.port,
            privkey,
        )

        blockchain = BlockChainService(
            privkey,
            rpc_client,
            GAS_PRICE,
        )
        blockchain_services.append(blockchain)

    return BlockchainServices(
        deploy_registry,
        deploy_blockchain,
        blockchain_services,
    )
