# -*- coding: utf-8 -*-
from __future__ import division

import json
import os

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


def _assets_addresses(asset_amount, number_of_assets, blockchain_services):
    chain = blockchain_services[0]

    result = list()
    for _ in range(number_of_assets):
        asset_address = chain.deploy_and_register_asset(
            contract_name='HumanStandardToken',
            contract_file='HumanStandardToken.sol',
            constructor_parameters=(asset_amount, 'raiden', 2, 'Rd'),
        )
        result.append(asset_address)

        # only the creator of the token starts with a balance, transfer from
        # the creator to the other nodes
        for transfer_to in blockchain_services[1:]:
            chain.asset(asset_address).transfer(
                privatekey_to_address(transfer_to.private_key),
                asset_amount // len(blockchain_services),
            )

    return result


def make_genesis_from_fixtures(request):
    '''
    Deploy all contracts the required by the fixtures into a tester and then
    serialize the accounts into a genesis block.

    Returns:
        dict: A dictionary representing the genesis block.
    '''

    # this will create the tester _and_ deploy the Registry
    private_keys = request.getfixturevalue('private_keys')
    blockchain_services = _tester_services(
        private_keys,
        request.getfixturevalue('tester_blockgas_limit'),
    )

    # create_network only register the assets, the contracts must be deployed
    # previously
    asset_contract_addresses = _assets_addresses(
        request.getfixturevalue('asset_amount'),
        request.getfixturevalue('number_of_assets'),
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

    else:
        # what is the fixture name?
        raise Exception('unknow network type')

    for app in raiden_apps:
        app.stop()

    # save the state from the last block into a genesis dict
    tester = blockchain_services[0].tester_state
    tester.mine()
    registry_address = blockchain_services[0].default_registry.address

    genesis_alloc = dict()
    for account_address in tester.block.state.to_dict():
        genesis_alloc[account_address] = account_alloc = dict()

        for key, value in tester.block.account_to_dict(account_address).iteritems():
            account_alloc[key] = safe_lstrip_hex(value)

    account_addresses = [
        privatekey_to_address(key)
        for key in set(private_keys)
    ]

    for address in account_addresses:
        genesis_alloc[address]['balance'] = DEFAULT_BALANCE_BIN

    alloc = {
        address_encoder(address_maybe_bin): data
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

    genesis_path = genesis_path_from_testfunction(request)

    if cached_genesis and os.path.exists(genesis_path):
        with open(genesis_path) as handler:
            genesis = json.load(handler)

        assets_addresses = [
            address_decoder(asset_address)
            for asset_address in genesis['config']['assetAddresses']
        ]
    else:
        assets_addresses = _assets_addresses(
            asset_amount,
            number_of_assets,
            blockchain_services,
        )

    return assets_addresses


@pytest.fixture
def blockchain_services(
        request,
        private_keys,
        poll_timeout,
        blockchain_backend,  # This fixture is required because it will start
                             # the geth subprocesses
        blockchain_type,
        tester_blockgas_limit,
        cached_genesis):

    verbose = request.config.option.verbose

    if blockchain_type in ('geth',):
        genesis_path = genesis_path_from_testfunction(request)
        registry_address = None

        if cached_genesis and os.path.exists(genesis_path):

            with open(genesis_path) as handler:
                genesis = json.load(handler)

            registry_address = address_decoder(genesis['config']['defaultRegistryAddress'])

        return _jsonrpc_services(
            private_keys,
            verbose,
            poll_timeout,
            registry_address,
        )

    if blockchain_type == 'tester':
        return _tester_services(
            private_keys,
            tester_blockgas_limit,
        )

    if blockchain_type == 'mock':
        return _mock_services(
            private_keys,
            request,
        )

    raise ValueError('unknow cluster type {}'.format(blockchain_type))


@pytest.fixture
def blockchain_backend(
        request,
        private_keys,
        blockchain_private_keys,
        blockchain_p2p_base_port,
        tmpdir,
        blockchain_type,
        cached_genesis):

    genesis_path = None
    if cached_genesis and blockchain_type in ('geth', ):
        genesis_path = genesis_path_from_testfunction(request)

        if not os.path.exists(genesis_path):
            genesis = make_genesis_from_fixtures(request)

            with open(genesis_path, 'w') as handler:
                json.dump(genesis, handler)

    if blockchain_type == 'geth':
        return _geth_blockchain(
            request,
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
        private_keys,
        cluster_private_keys,
        p2p_base_port,
        tmpdir,
        genesis_path):

    """ Helper to do proper cleanup. """
    verbosity = request.config.option.verbose

    geth_processes = geth_create_blockchain(
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


def _jsonrpc_services(private_keys, verbose, poll_timeout, registry_address=None):
    print_communication = True

    privatekey = private_keys[0]
    address = privatekey_to_address(privatekey)
    jsonrpc_client = JSONRPCClient(
        host='0.0.0.0',
        privkey=privatekey,
        print_communication=print_communication,
    )
    patch_send_transaction(jsonrpc_client)

    if registry_address is None:
        registry_path = get_contract_path('Registry.sol')
        registry_contracts = compile_file(registry_path, libraries=dict())

        log.info('Deploying registry contract')
        registry_proxy = jsonrpc_client.deploy_solidity_contract(
            address,
            'Registry',
            registry_contracts,
            dict(),
            tuple(),
            timeout=poll_timeout,
        )
        registry_address = registry_proxy.address

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainService(
            privkey,
            registry_address,
            '0.0.0.0',
            jsonrpc_client.port,
        )
        blockchain_services.append(blockchain)

    return blockchain_services


def _mock_services(private_keys, request):
    # make sure we are getting and leaving a clean state, just in case the
    # BlockChainServiceMock wasn't instantiate through the proper fixture.

    @request.addfinalizer
    def _cleanup():
        BlockChainServiceMock.reset()

    BlockChainServiceMock.reset()

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceMock(
            privkey,
            MOCK_REGISTRY_ADDRESS,
        )
        blockchain_services.append(blockchain)

    return blockchain_services


def _tester_services(private_keys, tester_blockgas_limit):
    # calling the fixture directly because we don't want to force all
    # blockchain_services to instantiate a state
    tester = tester_state(
        private_keys,
        tester_blockgas_limit,
    )

    tester_registry_address = tester_deploy_contract(
        tester,
        private_keys[0],
        contract_name='Registry',
        contract_file='Registry.sol',
    )

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceTesterMock(
            privkey,
            tester,
            tester_registry_address,
        )
        blockchain_services.append(blockchain)

    return blockchain_services
