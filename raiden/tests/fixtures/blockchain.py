# -*- coding: utf-8 -*-
from __future__ import division

import json
import os
from collections import namedtuple

import pytest
from ethereum import slogging
from ethereum._solidity import compile_file
from pyethapp.rpc_client import JSONRPCClient
from pyethapp.jsonrpc import address_decoder, address_encoder

from raiden.utils import privatekey_to_address, get_contract_path, safe_lstrip_hex
from raiden.tests.fixtures.tester import tester_state
from raiden.tests.utils.blockchain import GENESIS_STUB, DEFAULT_BALANCE_BIN
from raiden.tests.utils.mock_client import BlockChainServiceMock, MOCK_REGISTRY_ADDRESS
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.tester_client import tester_deploy_contract, BlockChainServiceTesterMock
from raiden.network.rpc.client import (
    patch_send_transaction,
    BlockChainService,
)
from raiden.tests.utils.blockchain import (
    geth_create_blockchain,
)
from raiden.tests.utils.network import (
    create_apps,
    create_network_channels,
    create_sequential_channels,
)

BlockchainServices = namedtuple(
    'BlockchainServices',
    ('deploy_service', 'blockchain_services'),
)
log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

__all__ = (
    'assets_addresses',
    'blockchain_services',
    'blockchain_backend',
)

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument


def genesis_path_from_testfunction(request):
    cached_dir = request.config.cache.makedir(request.node.name)
    genesis_path = cached_dir.join('generated_genesis.json')

    return str(genesis_path)  # makedir returns a py.path.LocalPath object


def _assets_addresses(asset_amount, number_of_assets, deploy_service, blockchain_services):
    result = list()
    for _ in range(number_of_assets):
        asset_address = deploy_service.deploy_and_register_asset(
            contract_name='HumanStandardToken',
            contract_file='HumanStandardToken.sol',
            constructor_parameters=(asset_amount, 'raiden', 2, 'Rd'),
        )
        result.append(asset_address)

        # only the creator of the token starts with a balance (deploy_service),
        # transfer from the creator to the other nodes
        for transfer_to in blockchain_services:
            deploy_service.asset(asset_address).transfer(
                privatekey_to_address(transfer_to.private_key),
                asset_amount // len(blockchain_services),
            )

    return result


@pytest.fixture
def cached_genesis(request, blockchain_type):
    '''
    Deploy all contracts the required by the fixtures into a tester and then
    serialize the accounts into a genesis block.

    Returns:
        dict: A dictionary representing the genesis block.
    '''

    if not request.config.option.blockchain_cache:
        return

    # cannot cache for mock blockchain
    if blockchain_type == 'mock':
        return

    # this will create the tester _and_ deploy the Registry
    deploy_key = request.getfixturevalue('deploy_key')
    private_keys = request.getfixturevalue('private_keys')
    deploy_service, blockchain_services = _tester_services(
        deploy_key,
        private_keys,
        request.getfixturevalue('tester_blockgas_limit'),
    )

    # create_network only register the assets, the contracts must be deployed
    # previously
    asset_contract_addresses = _assets_addresses(
        request.getfixturevalue('asset_amount'),
        request.getfixturevalue('number_of_assets'),
        deploy_service,
        blockchain_services,
    )

    raiden_apps = create_apps(
        blockchain_services,
        request.getfixturevalue('transport_class'),
        request.config.option.verbose,
    )

    if 'raiden_network' in request.fixturenames:
        create_network_channels(
            raiden_apps,
            asset_contract_addresses,
            request.getfixturevalue('channels_per_node'),
            request.getfixturevalue('deposit'),
            request.getfixturevalue('settle_timeout'),
        )

    elif 'raiden_chain' in request.fixturenames:
        create_sequential_channels(
            raiden_apps,
            asset_contract_addresses[0],
            request.getfixturevalue('channels_per_node'),
            request.getfixturevalue('deposit'),
            request.getfixturevalue('settle_timeout'),
        )

    # else: a test that is not creating channels

    for app in raiden_apps:
        app.stop()

    # save the state from the last block into a genesis dict
    tester = blockchain_services[0].tester_state
    tester.mine()
    registry_address = blockchain_services[0].default_registry.address

    genesis_alloc = dict()
    for account_address in tester.block.state.to_dict():
        account_alloc = tester.block.account_to_dict(account_address)

        # code must be hex encoded without 0x prefix
        account_alloc['code'] = safe_lstrip_hex(account_alloc.get('code', ''))

        # account_to_dict returns accounts with nonce=0
        account_alloc['nonce'] = tester.block.get_nonce(account_address)

        genesis_alloc[account_address] = account_alloc

    account_addresses = [
        privatekey_to_address(key)
        for key in set(private_keys)
    ]

    for address in account_addresses:
        genesis_alloc[address]['balance'] = DEFAULT_BALANCE_BIN

    alloc = {
        safe_lstrip_hex(address_encoder(address_maybe_bin)): data
        for address_maybe_bin, data in genesis_alloc.iteritems()
    }

    genesis = GENESIS_STUB.copy()
    genesis['alloc'] = alloc
    genesis['config']['defaultRegistryAddress'] = address_encoder(registry_address)
    genesis['config']['assetAddresses'] = [
        address_encoder(asset_address)
        for asset_address in asset_contract_addresses
    ]

    return genesis


@pytest.fixture
def assets_addresses(
        request,
        asset_amount,
        number_of_assets,
        blockchain_services,
        cached_genesis):

    if cached_genesis:
        assets_addresses = [
            address_decoder(asset_address)
            for asset_address in cached_genesis['config']['assetAddresses']
        ]
    else:
        assets_addresses = _assets_addresses(
            asset_amount,
            number_of_assets,
            blockchain_services.deploy_service,
            blockchain_services.blockchain_services,
        )

    return assets_addresses


@pytest.fixture
def blockchain_services(
        request,
        deploy_key,
        private_keys,
        poll_timeout,
        blockchain_backend,  # This fixture is required because it will start
                             # the geth subprocesses
        blockchain_type,
        tester_blockgas_limit,
        cached_genesis):

    verbose = request.config.option.verbose

    if blockchain_type in ('geth',):

        registry_address = None
        if cached_genesis:
            registry_address = cached_genesis['config'].get('defaultRegistryAddress')

            if registry_address:
                registry_address = address_decoder(registry_address)

        return _jsonrpc_services(
            deploy_key,
            private_keys,
            verbose,
            poll_timeout,
            registry_address,
        )

    if blockchain_type == 'tester':
        return _tester_services(
            deploy_key,
            private_keys,
            tester_blockgas_limit,
        )

    if blockchain_type == 'mock':
        return _mock_services(
            deploy_key,
            private_keys,
            request,
        )

    raise ValueError('unknow cluster type {}'.format(blockchain_type))


@pytest.fixture
def blockchain_backend(
        request,
        deploy_key,
        private_keys,
        blockchain_private_keys,
        blockchain_p2p_base_port,
        tmpdir,
        blockchain_type,
        cached_genesis):

    genesis_path = None
    if cached_genesis:
        genesis_path = genesis_path_from_testfunction(request)

    if blockchain_type == 'geth':
        if genesis_path and not os.path.exists(genesis_path):
            with open(genesis_path, 'w') as handler:
                json.dump(cached_genesis, handler)

        return _geth_blockchain(
            request,
            deploy_key,
            private_keys,
            blockchain_private_keys,
            blockchain_p2p_base_port,
            tmpdir,
            genesis_path,
        )

    if blockchain_type == 'tester':
        return ()

    if blockchain_type == 'mock':
        return ()

    # check pytest_addoption
    raise ValueError('unknow cluster type {}'.format(blockchain_type))


def _geth_blockchain(
        request,
        deploy_key,
        private_keys,
        cluster_private_keys,
        p2p_base_port,
        tmpdir,
        genesis_path):

    """ Helper to do proper cleanup. """
    verbosity = request.config.option.verbose

    geth_processes = geth_create_blockchain(
        deploy_key,
        private_keys,
        cluster_private_keys,
        p2p_base_port,
        str(tmpdir),
        verbosity,
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
        private_keys,
        verbose,
        poll_timeout,
        registry_address=None):

    host = '0.0.0.0'
    deploy_client = JSONRPCClient(host=host, privkey=deploy_key)

    # we cannot instantiate BlockChainService without a registry, so first
    # deploy it directly with a JSONRPCClient
    if registry_address is None:
        address = privatekey_to_address(deploy_key)
        patch_send_transaction(deploy_client)

        registry_path = get_contract_path('Registry.sol')
        registry_contracts = compile_file(registry_path, libraries=dict())

        log.info('Deploying registry contract')
        registry_proxy = deploy_client.deploy_solidity_contract(
            address,
            'Registry',
            registry_contracts,
            dict(),
            tuple(),
            timeout=poll_timeout,
        )
        registry_address = registry_proxy.address

    deploy_blockchain = BlockChainService(
        deploy_key,
        registry_address,
        host,
        deploy_client.port,
    )

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainService(
            privkey,
            registry_address,
            host,
            deploy_client.port,
        )
        blockchain_services.append(blockchain)

    return BlockchainServices(deploy_blockchain, blockchain_services)


def _mock_services(deploy_key, private_keys, request):
    # make sure we are getting and leaving a clean state, just in case the
    # BlockChainServiceMock wasn't instantiate through the proper fixture.

    @request.addfinalizer
    def _cleanup():
        BlockChainServiceMock.reset()

    BlockChainServiceMock.reset()

    deploy_blockchain = BlockChainServiceMock(deploy_key, MOCK_REGISTRY_ADDRESS)

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceMock(
            privkey,
            MOCK_REGISTRY_ADDRESS,
        )
        blockchain_services.append(blockchain)

    return BlockchainServices(deploy_blockchain, blockchain_services)


def _tester_services(deploy_key, private_keys, tester_blockgas_limit):
    # calling the fixture directly because we don't want to force all
    # blockchain_services to instantiate a state
    tester = tester_state(
        deploy_key,
        private_keys,
        tester_blockgas_limit,
    )

    tester_registry_address = tester_deploy_contract(
        tester,
        deploy_key,
        contract_name='Registry',
        contract_file='Registry.sol',
    )

    deploy_blockchain = BlockChainServiceTesterMock(
        deploy_key,
        tester,
        tester_registry_address,
    )

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceTesterMock(
            privkey,
            tester,
            tester_registry_address,
        )
        blockchain_services.append(blockchain)

    return BlockchainServices(deploy_blockchain, blockchain_services)
