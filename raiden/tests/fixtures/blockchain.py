# -*- coding: utf8 -*-
import pytest
from ethereum import slogging
from ethereum.keys import privtoaddr
from ethereum._solidity import compile_file
from pyethapp.rpc_client import address_encoder, JSONRPCClient

from raiden.blockchain import get_contract_path
from raiden.utils import sha3
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.mock_client import BlockChainServiceMock, MOCK_REGISTRY_ADDRESS
from raiden.tests.utils.tester_client import BlockChainServiceTesterMock
from raiden.network.rpc.client import (
    patch_send_transaction,
    BlockChainService,
    DEFAULT_POLL_TIMEOUT,
)
from raiden.tests.utils.network import (
    geth_create_blockchain,
    hydrachain_create_blockchain,
    tester_create_blockchain,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def _jsonrpc_services(private_keys, verbose, blockchain_poll_timeout):
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
        timeout=blockchain_poll_timeout,
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
    @request.addfinalizer
    def _cleanup():
        BlockChainServiceMock._instance = None

    # pylint: disable=protected-access,redefined-variable-type
    BlockChainServiceMock._instance = True
    blockchain_service = BlockChainServiceMock(None, MOCK_REGISTRY_ADDRESS)
    BlockChainServiceMock._instance = blockchain_service
    # pylint: enable=protected-access,redefined-variable-type

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceMock(
            privkey,
            MOCK_REGISTRY_ADDRESS,
        )
        blockchain_services.append(blockchain)

    return blockchain_services


def _tester_services(private_keys):
    tester_state = tester_create_blockchain(private_keys)

    netting_library_path = get_contract_path('NettingChannelLibrary.sol')
    netting_library_address = tester_state.contract(
        None,
        path=netting_library_path,
        language='solidity',
        contract_name='NettingChannelLibrary',
    )

    channelmanager_library_path = get_contract_path('ChannelManagerLibrary.sol')
    channelmanager_library_address = tester_state.contract(
        None,
        path=channelmanager_library_path,
        language='solidity',
        contract_name='ChannelManagerLibrary',
        libraries={
            'NettingChannelLibrary': address_encoder(netting_library_address),
        }
    )

    registry_path = get_contract_path('Registry.sol')
    registry_address = tester_state.contract(
        None,
        path=registry_path,
        language='solidity',
        contract_name='Registry',
        libraries={
            'ChannelManagerLibrary': address_encoder(channelmanager_library_address)
        }
    )

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceTesterMock(
            privkey,
            tester_state,
            registry_address,
        )
        blockchain_services.append(blockchain)

    return blockchain_services


@pytest.fixture
def blockchain_number_of_nodes():
    """ Number of nodes in a the cluster, not the same as the number of raiden
    nodes. Used for all hydrachain and geth clusters and ignored for tester and
    mock.
    """
    return 3


@pytest.fixture
def blockchain_key_seed():
    """ Private key template for the nodes in the private blockchain, allows
    different keys to be used for each test to avoid collisions.
    """
    return 'cluster:{}'


@pytest.fixture
def blockchain_private_keys(blockchain_number_of_nodes, blockchain_key_seed):
    """ The private keys for the each private chain node, not the same as the
    raiden's private key.
    """
    return [
        sha3(blockchain_key_seed.format(position))
        for position in range(blockchain_number_of_nodes)
    ]


# TODO: return a base port that is not random and guaranteed to be used
# only once (avoid that a badly cleaned test interfere with the next).
@pytest.fixture
def blockchain_p2p_base_port():
    """ Default P2P base port. """
    return 29870


@pytest.fixture
def blockchain_poll_timeout():
    """ Timeout in seconds for polling a cluster. Used for geth and hydrachain. """
    return DEFAULT_POLL_TIMEOUT


@pytest.fixture
def blockchain_services(request, private_keys, blockchain_poll_timeout):
    cluster_type = request.config.option.cluster_type
    verbose = request.config.option.verbose

    if cluster_type in ('geth', 'hydrachain'):
        return _jsonrpc_services(
            private_keys,
            verbose,
            blockchain_poll_timeout,
        )

    if cluster_type == 'tester':
        return _tester_services(
            private_keys,
        )

    if cluster_type == 'mock':
        return _mock_services(
            private_keys,
            request,
        )

    raise ValueError('unknow cluster type {}'.format(cluster_type))


@pytest.fixture
def blockchain(request, private_keys, blockchain_private_keys,
               blockchain_p2p_base_port, tmpdir):
    blockchain_type = request.config.option.blockchain_type

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
