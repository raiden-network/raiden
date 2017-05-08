# -*- coding: utf-8 -*-
from __future__ import division

import json
import os
import subprocess
from collections import namedtuple

import pytest
from ethereum import slogging
from ethereum._solidity import compile_file
from pyethapp.rpc_client import JSONRPCClient
from pyethapp.jsonrpc import address_decoder, address_encoder, default_gasprice

from raiden.utils import privatekey_to_address, get_contract_path
from raiden.network.transport import DummyTransport
from raiden.tests.fixtures.tester import tester_state
from raiden.tests.utils.blockchain import GENESIS_STUB, DEFAULT_BALANCE_BIN
from raiden.tests.utils.mock_client import BlockChainServiceMock, MOCK_REGISTRY_ADDRESS
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.tester_client import tester_deploy_contract, BlockChainServiceTesterMock
from raiden.network.rpc.client import (
    patch_send_transaction,
    patch_send_message,
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
EPOCH0_DAGSIZE = 1073739912

__all__ = (
    'token_addresses',
    'register_tokens',
    'blockchain_services',
    'blockchain_backend',
)

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals


def genesis_path_from_testfunction(request):
    cached_dir = request.config.cache.makedir(request.node.name)
    genesis_path = cached_dir.join('generated_genesis.json')

    return str(genesis_path)  # makedir returns a py.path.LocalPath object


def _token_addresses(
    token_amount,
    number_of_tokens,
    deploy_service,
    blockchain_services,
    register
):
    result = list()
    for _ in range(number_of_tokens):
        if register:
            token_address = deploy_service.deploy_and_register_token(
                contract_name='HumanStandardToken',
                contract_file='HumanStandardToken.sol',
                constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
            )
            result.append(token_address)
        else:
            token_address = deploy_service.deploy_contract(
                contract_name='HumanStandardToken',
                contract_file='HumanStandardToken.sol',
                constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
            )
            result.append(token_address)

        # only the creator of the token starts with a balance (deploy_service),
        # transfer from the creator to the other nodes
        for transfer_to in blockchain_services:
            deploy_service.token(token_address).transfer(
                privatekey_to_address(transfer_to.private_key),
                token_amount // len(blockchain_services),
            )

    return result


@pytest.fixture()
def dagpath():
    return os.path.expanduser('~/.ethash/full-R23-0000000000000000')


@pytest.fixture(scope='session', autouse=True)
def pregenerate_dag(request, blockchain_type, dagpath):
    missing_dag = (
        not os.path.exists(dagpath) or
        os.path.getsize(dagpath) != EPOCH0_DAGSIZE
    )

    if blockchain_type == 'geth' and missing_dag:
        dag_folder = os.path.dirname(dagpath)
        os.makedirs(dag_folder)

        makedag = subprocess.Popen(['geth', 'makedag', '0', dag_folder])
        makedag.communicate()
        assert makedag.returncode == 0, 'DAG generation failed'


@pytest.fixture
def cached_genesis(request, blockchain_type):
    """
    Deploy all contracts that are required by the fixtures into a tester and
    then serialize the accounts into a genesis block.

    Returns:
        dict: A dictionary representing the genesis block.
    """

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

    # create_network only registers the tokens,
    # the contracts must be deployed previously
    register = True
    token_contract_addresses = _token_addresses(
        request.getfixturevalue('token_amount'),
        request.getfixturevalue('number_of_tokens'),
        deploy_service,
        blockchain_services,
        register
    )

    raiden_apps = create_apps(
        blockchain_services,
        request.getfixturevalue('raiden_udp_ports'),
        DummyTransport,  # Do not use a UDP server to avoid port reuse in MacOSX
        request.config.option.verbose,
        request.getfixturevalue('send_ping_time'),
        request.getfixturevalue('max_unresponsive_time'),
        request.getfixturevalue('reveal_timeout'),
        request.getfixturevalue('settle_timeout'),
        request.getfixturevalue('database_paths'),
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
        app.stop()

    # save the state from the last block into a genesis dict
    tester = blockchain_services[0].tester_state
    tester.mine()
    registry_address = blockchain_services[0].default_registry.address

    genesis_alloc = dict()
    for account_address in tester.block.state.to_dict():
        account_alloc = tester.block.account_to_dict(account_address)

        # Both keys and values of the account storage associative array
        # must now be encoded with 64 hex digits
        if account_alloc['storage']:
            new_storage = dict()
            for key, val in account_alloc['storage'].iteritems():
                # account_to_dict() from pyethereum can return 0x for a storage
                # position. That is an invalid way of representing 0x0, which we
                # have to take care of here.
                new_key = '0x%064x' % int(key if key != '0x' else '0x0', 16)
                new_val = '0x%064x' % int(val, 16)
                new_storage[new_key] = new_val

            account_alloc['storage'] = new_storage

        # code must be hex encoded with 0x prefix
        account_alloc['code'] = account_alloc.get('code', '')

        # account_to_dict returns accounts with nonce=0 and the nonce must
        # be encoded with 16 hex digits
        account_alloc['nonce'] = '0x%016x' % tester.block.get_nonce(account_address)

        genesis_alloc[account_address] = account_alloc

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
    genesis['config']['tokenAddresses'] = [
        address_encoder(token_address)
        for token_address in token_contract_addresses
    ]

    return genesis


@pytest.fixture
def register_tokens():
    """Should fixture generated tokens be registered with raiden (default: True)
    """
    return True


@pytest.fixture
def token_addresses(
        request,
        token_amount,
        number_of_tokens,
        blockchain_services,
        cached_genesis,
        register_tokens):

    if cached_genesis:
        token_addresses = [
            address_decoder(token_address)
            for token_address in cached_genesis['config']['tokenAddresses']
        ]
    else:
        token_addresses = _token_addresses(
            token_amount,
            number_of_tokens,
            blockchain_services.deploy_service,
            blockchain_services.blockchain_services,
            register_tokens
        )

    return token_addresses


@pytest.fixture
def blockchain_services(
        request,
        deploy_key,
        private_keys,
        poll_timeout,
        blockchain_backend,  # This fixture is required because it will start
                             # the geth subprocesses
        blockchain_rpc_ports,
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
            blockchain_rpc_ports[0],
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

    raise ValueError('unknown cluster type {}'.format(blockchain_type))


@pytest.fixture
def blockchain_backend(
        request,
        deploy_key,
        private_keys,
        blockchain_private_keys,
        blockchain_p2p_ports,
        blockchain_rpc_ports,
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
            blockchain_p2p_ports,
            blockchain_rpc_ports,
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
        blockchain_private_keys,
        blockchain_p2p_ports,
        blockchain_rpc_ports,
        tmpdir,
        genesis_path):

    """ Helper to do proper cleanup. """
    verbosity = request.config.option.verbose

    geth_processes = geth_create_blockchain(
        deploy_key,
        private_keys,
        blockchain_private_keys,
        blockchain_rpc_ports,
        blockchain_p2p_ports,
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
        rpc_port,
        registry_address=None):

    host = '0.0.0.0'
    print_communication = verbose > 6
    deploy_client = JSONRPCClient(
        host=host,
        port=rpc_port,
        privkey=deploy_key,
        print_communication=print_communication,
    )

    # we cannot instantiate BlockChainService without a registry, so first
    # deploy it directly with a JSONRPCClient
    if registry_address is None:
        address = privatekey_to_address(deploy_key)
        patch_send_transaction(deploy_client)
        patch_send_message(deploy_client)

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
            gasprice=default_gasprice,
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
    # BlockChainServiceMock wasn't instantiated through the proper fixture.

    @request.addfinalizer
    def _cleanup():  # pylint: disable=unused-variable
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
