# -*- coding: utf-8 -*-
import json
from binascii import hexlify
from os import path
from collections import namedtuple

import pytest
from ethereum import slogging
from ethereum.tools._solidity import compile_file

from raiden.utils import (
    address_decoder,
    address_encoder,
    fix_tester_storage,
    get_contract_path,
    privatekey_to_address,
)
from raiden.network.transport import DummyTransport
from raiden.tests.fixtures.tester import tester_chain
from raiden.tests.utils.blockchain import GENESIS_STUB, DEFAULT_BALANCE_BIN
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.tester_client import tester_deploy_contract, BlockChainServiceTesterMock
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.blockchain import (
    clique_extradata,
    geth_create_blockchain,
)
from raiden.tests.utils.network import (
    create_apps,
    create_network_channels,
    create_sequential_channels,
)
from raiden.settings import GAS_PRICE

BlockchainServices = namedtuple(
    'BlockchainServices',
    (
        'deploy_registry',
        'deploy_service',
        'blockchain_services',
    )
)
log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


def _token_addresses(
        token_amount,
        number_of_tokens,
        deploy_service,
        registry,
        participants,
        register):
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
def cached_genesis(request):
    """
    Deploy all contracts that are required by the fixtures into a tester and
    then serialize the accounts into a genesis block.

    Returns:
        dict: A dictionary representing the genesis block.
    """

    if not request.config.option.blockchain_cache:
        return

    # this will create the tester _and_ deploy the Registry
    deploy_key = request.getfixturevalue('deploy_key')
    private_keys = request.getfixturevalue('private_keys')
    registry, deploy_service, blockchain_services = _tester_services(
        deploy_key,
        private_keys,
        request.getfixturevalue('tester_blockgas_limit'),
    )

    registry_address = registry.address

    # create_network only registers the tokens,
    # the contracts must be deployed previously
    register = True
    participants = [privatekey_to_address(privatekey) for privatekey in private_keys]
    token_contract_addresses = _token_addresses(
        request.getfixturevalue('token_amount'),
        request.getfixturevalue('number_of_tokens'),
        deploy_service,
        registry,
        participants,
        register
    )

    endpoint_discovery_address = deploy_service.deploy_contract(
        'EndpointRegistry',
        get_contract_path('EndpointRegistry.sol'),
    )

    endpoint_discovery_services = [
        ContractDiscovery(
            chain.node_address,
            chain.discovery(endpoint_discovery_address),
        )
        for chain in blockchain_services
    ]

    raiden_apps = create_apps(
        blockchain_services,
        endpoint_discovery_services,
        registry_address,
        request.getfixturevalue('raiden_udp_ports'),
        DummyTransport,  # Do not use a UDP server to avoid port reuse in MacOSX
        request.getfixturevalue('reveal_timeout'),
        request.getfixturevalue('settle_timeout'),
        request.getfixturevalue('database_paths'),
        request.getfixturevalue('retry_interval'),
        request.getfixturevalue('retries_before_backoff'),
        request.getfixturevalue('throttle_capacity'),
        request.getfixturevalue('throttle_fill_rate'),
        request.getfixturevalue('nat_invitation_timeout'),
        request.getfixturevalue('nat_keepalive_retries'),
        request.getfixturevalue('nat_keepalive_timeout'),
    )

    if 'raiden_network' in request.fixturenames:
        create_network_channels(
            raiden_apps,
            token_contract_addresses,
            request.getfixturevalue('channels_per_node'),
            request.getfixturevalue('deposit'),
            request.getfixturevalue('settle_timeout'),
        )

    elif 'raiden_chain' in request.fixturenames:
        create_sequential_channels(
            raiden_apps,
            token_contract_addresses[0],
            request.getfixturevalue('channels_per_node'),
            request.getfixturevalue('deposit'),
            request.getfixturevalue('settle_timeout'),
        )

    # else: a test that is not creating channels

    for app in raiden_apps:
        app.stop(leave_channels=False)

    # save the state from the last block into a genesis dict
    tester = blockchain_services[0].tester_chain
    tester.mine()

    genesis_alloc = dict()
    for account_address in tester.head_state.to_dict():
        account_alloc = tester.head_state.account_to_dict(account_address)

        # Both keys and values of the account storage associative array
        # must now be encoded with 64 hex digits
        if account_alloc['storage']:
            account_alloc['storage'] = fix_tester_storage(account_alloc['storage'])

        # code must be hex encoded with 0x prefix
        account_alloc['code'] = account_alloc.get('code', '')

        # account_to_dict returns accounts with nonce=0 and the nonce must
        # be encoded with 16 hex digits
        account_alloc['nonce'] = '0x%016x' % tester.head_state.get_nonce(account_address)

        genesis_alloc[account_address] = account_alloc

    all_keys = set(private_keys)
    all_keys.add(deploy_key)
    all_keys = sorted(all_keys)
    account_addresses = [
        privatekey_to_address(key)
        for key in all_keys
    ]

    for address in account_addresses:
        address_hex = hexlify(address).decode()
        genesis_alloc[address_hex]['balance'] = DEFAULT_BALANCE_BIN

    genesis = GENESIS_STUB.copy()
    genesis['config']['clique'] = {'period': 1, 'epoch': 30000}

    random_marker = request.getfixturevalue('random_marker')
    genesis['extraData'] = clique_extradata(
        random_marker,
        address_encoder(account_addresses[0])[2:],
    )
    genesis['alloc'] = genesis_alloc
    genesis['config']['defaultDiscoveryAddress'] = address_encoder(endpoint_discovery_address)
    genesis['config']['defaultRegistryAddress'] = address_encoder(registry_address)
    genesis['config']['tokenAddresses'] = [
        address_encoder(token_address)
        for token_address in token_contract_addresses
    ]

    return genesis


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
        cached_genesis,
        register_tokens):
    """ Fixture that yields `number_of_tokens` ERC20 token addresses, where the
    `token_amount` (per token) is distributed among the addresses behind `blockchain_services` and
    potentially pre-registered with the raiden Registry.
    The following arguments can control the behavior:

    Args:
        token_amount (int): the overall number of units minted per token
        number_of_tokens (int): the number of token instances
        register_tokens (bool): controls if tokens will be registered with raiden Registry
    """

    if cached_genesis:
        token_addresses = [
            address_decoder(token_address)
            for token_address in cached_genesis['config']['tokenAddresses']
        ]
    else:
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
        tester_blockgas_limit,
        cached_genesis):

    registry_address = None
    if cached_genesis and 'defaultRegistryAddress' in cached_genesis['config']:
        registry_address = address_decoder(
            cached_genesis['config']['defaultRegistryAddress']
        )

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
def endpoint_discovery_services(blockchain_services, cached_genesis):
    discovery_address = None

    if cached_genesis and 'defaultDiscoveryAddress' in cached_genesis['config']:
        discovery_address = address_decoder(
            cached_genesis['config']['defaultDiscoveryAddress']
        )

    if discovery_address is None:
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
        cached_genesis):

    genesis_path = None
    if cached_genesis:
        genesis_path = path.join(str(tmpdir), 'generated_genesis.json')

        with open(genesis_path, 'w') as handler:
            json.dump(cached_genesis, handler)

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
        registry_address=None):

    # we cannot instantiate BlockChainService without a registry, so first
    # deploy it directly with a JSONRPCClient
    if registry_address is None:
        address = privatekey_to_address(deploy_key)

        registry_path = get_contract_path('Registry.sol')
        registry_contracts = compile_file(registry_path, libraries=dict())

        log.info('Deploying registry contract')
        registry_proxy = deploy_client.deploy_solidity_contract(
            address,
            'Registry',
            registry_contracts,
            dict(),
            tuple(),
            contract_path=registry_path,
            timeout=poll_timeout,
        )
        registry_address = registry_proxy.contract_address

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


def _tester_services(deploy_key, private_keys, tester_blockgas_limit):
    # calling the fixture directly because we don't want to force all
    # blockchain_services to instantiate a state
    tester = tester_chain(
        deploy_key,
        private_keys,
        tester_blockgas_limit,
    )

    tester_registry_address = tester_deploy_contract(
        tester,
        deploy_key,
        contract_name='Registry',
        contract_path=get_contract_path('Registry.sol'),
    )

    deploy_blockchain = BlockChainServiceTesterMock(
        deploy_key,
        tester,
    )

    deploy_registry = deploy_blockchain.registry(tester_registry_address)

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceTesterMock(
            privkey,
            tester,
        )
        blockchain_services.append(blockchain)

    return BlockchainServices(
        deploy_registry,
        deploy_blockchain,
        blockchain_services,
    )
