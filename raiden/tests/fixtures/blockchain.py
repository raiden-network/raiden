# -*- coding: utf8 -*-
from __future__ import division

import pytest
from ethereum import slogging
from ethereum.keys import privtoaddr
from ethereum._solidity import compile_file
from pyethapp.rpc_client import JSONRPCClient

from raiden.blockchain.abi import get_contract_path
from raiden.tests.fixtures.tester import tester_state
from raiden.tests.utils.mock_client import BlockChainServiceMock, MOCK_REGISTRY_ADDRESS
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.tester_client import tester_deploy_contract, BlockChainServiceTesterMock
from raiden.network.rpc.client import (
    patch_send_transaction,
    BlockChainService,
)
from raiden.tests.utils.blockchain import (
    geth_create_blockchain,
    hydrachain_create_blockchain,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

__all__ = (
    'assets_addresses',
    'blockchain_services',
    'blockchain_backend',
)


@pytest.fixture
def assets_addresses(asset_amount, number_of_assets, blockchain_services):
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
                privtoaddr(transfer_to.private_key),
                asset_amount // len(blockchain_services),
            )

    return result


@pytest.fixture
def blockchain_services(request, private_keys, poll_timeout, blockchain_backend, blockchain_type, tester_blockgas_limit):
    verbose = request.config.option.verbose

    if blockchain_type in ('geth', 'hydrachain'):
        return _jsonrpc_services(
            private_keys,
            verbose,
            poll_timeout,
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
def blockchain_backend(request, private_keys, blockchain_private_keys,
                       blockchain_p2p_base_port, tmpdir, blockchain_type):

    if blockchain_type == 'geth':
        return _geth_blockchain(
            request,
            private_keys,
            blockchain_private_keys,
            blockchain_p2p_base_port,
            tmpdir,
        )

    if blockchain_type == 'hydrachain':
        return _hydrachain_blockchain(
            request,
            private_keys,
            blockchain_private_keys,
            blockchain_p2p_base_port,
            tmpdir,
        )

    if blockchain_type == 'tester':
        return ()

    if blockchain_type == 'mock':
        return ()

    # check pytest_addoption
    raise ValueError('unknow cluster type {}'.format(blockchain_type))


def _hydrachain_blockchain(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    """ Helper to do proper cleanup. """
    hydrachain_apps = hydrachain_create_blockchain(
        private_keys,
        cluster_private_keys,
        p2p_base_port,
        str(tmpdir),
    )

    def _cleanup():
        for app in hydrachain_apps:
            app.stop()

        cleanup_tasks()

    request.addfinalizer(_cleanup)
    return hydrachain_apps


def _geth_blockchain(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    """ Helper to do proper cleanup. """
    verbosity = request.config.option.verbose

    geth_processes = geth_create_blockchain(
        private_keys,
        cluster_private_keys,
        p2p_base_port,
        str(tmpdir),
        verbosity,
    )

    def _cleanup():
        for process in geth_processes:
            process.terminate()

        cleanup_tasks()

    request.addfinalizer(_cleanup)
    return geth_processes


def _jsonrpc_services(private_keys, verbose, poll_timeout):
    print_communication = True if verbose > 7 else False

    privatekey = private_keys[0]
    address = privtoaddr(privatekey)
    jsonrpc_client = JSONRPCClient(
        host='0.0.0.0',
        privkey=privatekey,
        print_communication=print_communication,
    )
    patch_send_transaction(jsonrpc_client)

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
