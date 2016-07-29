# -*- coding: utf8 -*-
import pytest
import gevent
import gevent.monkey
from ethereum.keys import privtoaddr, PBKDF2_CONSTANTS
from ethereum._solidity import compile_file
from pyethapp.rpc_client import JSONRPCClient

from raiden.utils import sha3
from raiden.tests.utils.tests import cleanup_tasks
from raiden.network.transport import UDPTransport
from raiden.network.rpc.client import (
    patch_send_transaction,
    BlockChainService,
    BlockChainServiceMock,
    DEFAULT_POLL_TIMEOUT,
    GAS_LIMIT,
    MOCK_REGISTRY_ADDRESS,
)
from raiden.blockchain.abi import get_contract_path
from raiden.app import DEFAULT_SETTLE_TIMEOUT
from raiden.tests.utils.network import (
    create_network,
    create_sequential_network,
    create_hydrachain_cluster,
    create_geth_cluster,
    CHAIN,
    DEFAULT_DEPOSIT,
)

# we need to use fixture for the default values otherwise
# pytest.mark.parametrize won't work (pytest 2.9.2)

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals

# otherwise running hydrachain will block the test
gevent.monkey.patch_socket()
gevent.get_hub().SYSTEM_ERROR = BaseException
PBKDF2_CONSTANTS['c'] = 100


def _raiden_cleanup(request, raiden_apps):
    def _cleanup():
        for app in raiden_apps:
            app.stop()

        # kill all leftover tasklets
        cleanup_tasks()
    request.addfinalizer(_cleanup)


@pytest.fixture
def cluster_key_seed():
    return 'cluster:{}'


@pytest.fixture
def cluster_number_of_nodes():
    return 3


@pytest.fixture
def p2p_base_port():
    # TODO: return a base port that is not random and guaranteed to be used
    # only once (avoid that a badly cleaned test interfere with the next).
    return 29870


@pytest.fixture
def number_of_nodes():
    """ Number of raiden nodes. """
    return 3


@pytest.fixture
def settle_timeout():
    return DEFAULT_SETTLE_TIMEOUT


@pytest.fixture
def poll_timeout():
    return DEFAULT_POLL_TIMEOUT


@pytest.fixture
def privatekey_seed():
    """ Raiden private key template. """
    return 'key:{}'


@pytest.fixture
def private_keys(number_of_nodes, privatekey_seed):
    return [
        sha3(privatekey_seed.format(position))
        for position in range(number_of_nodes)
    ]


@pytest.fixture
def cluster_private_keys(cluster_number_of_nodes, cluster_key_seed):
    return [
        sha3(cluster_key_seed.format(position))
        for position in range(cluster_number_of_nodes)
    ]


@pytest.fixture
def hydrachain_cluster(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    hydrachain_apps = create_hydrachain_cluster(
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


@pytest.fixture
def geth_cluster(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    geth_processes = create_geth_cluster(
        private_keys,
        cluster_private_keys,
        p2p_base_port,
        str(tmpdir),
    )

    def _cleanup():
        for process in geth_processes:
            process.terminate()

        # Then kill any remaining tasklet
        cleanup_tasks()

    request.addfinalizer(_cleanup)
    return geth_processes


@pytest.fixture
def cluster(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    return geth_cluster(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir)


@pytest.fixture
def asset():
    """ Raiden chain asset. """
    return sha3('asset')[:20]


@pytest.fixture
def deposit():
    """ Raiden chain default deposit. """
    return DEFAULT_DEPOSIT


@pytest.fixture
def registry_address():
    return MOCK_REGISTRY_ADDRESS


@pytest.fixture
def number_of_assets():
    return 1


@pytest.fixture
def assets_addresses(number_of_assets):
    return [
        sha3('asset:{}'.format(number))[:20]
        for number in range(number_of_assets)
    ]


@pytest.fixture
def channels_per_node():
    """ Number of channels per node in for the raiden_network fixture. """
    return 1


@pytest.fixture
def transport_class():
    return UDPTransport


@pytest.fixture
def blockchain_service(request, registry_address):
    """ A mock blockchain for faster testing. """
    # pylint: disable=protected-access
    def _cleanup():
        BlockChainServiceMock._instance = None

    request.addfinalizer(_cleanup)

    # allows the fixture to instantiate the blockchain
    BlockChainServiceMock._instance = True

    blockchain_service = BlockChainServiceMock(None, registry_address)

    # overwrite the instance
    BlockChainServiceMock._instance = blockchain_service  # pylint: disable=redefined-variable-type

    return blockchain_service


@pytest.fixture
def raiden_chain(request, private_keys, asset, channels_per_node, deposit,
                 settle_timeout, poll_timeout, registry_address, blockchain_service,
                 transport_class):
    blockchain_service_class = BlockChainServiceMock

    registry = blockchain_service.registry(registry_address)
    registry.add_asset(asset)

    raiden_apps = create_sequential_network(
        private_keys,
        asset,
        registry_address,
        channels_per_node,
        deposit,
        settle_timeout,
        poll_timeout,
        transport_class,
        blockchain_service_class,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture
def raiden_network(request, private_keys, assets_addresses, channels_per_node,
                   deposit, settle_timeout, poll_timeout, registry_address, blockchain_service,
                   transport_class):
    blockchain_service_class = BlockChainServiceMock

    registry = blockchain_service.registry(registry_address)

    for asset in assets_addresses:
        registry.add_asset(asset)

    raiden_apps = create_network(
        private_keys,
        assets_addresses,
        registry_address,
        channels_per_node,
        deposit,
        settle_timeout,
        poll_timeout,
        transport_class,
        blockchain_service_class,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture
def deployed_network(request, private_keys, channels_per_node, deposit,
                     number_of_assets, settle_timeout, poll_timeout,
                     transport_class, geth_cluster):

    gevent.sleep(2)
    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

    privatekey = private_keys[0]
    address = privtoaddr(privatekey)
    blockchain_service_class = BlockChainService

    jsonrpc_client = JSONRPCClient(
        host='0.0.0.0',
        privkey=privatekey,
        print_communication=False,
    )
    patch_send_transaction(jsonrpc_client)

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    registry_path = get_contract_path('Registry.sol')

    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
    registry_contracts = compile_file(registry_path, libraries=dict())

    registry_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'Registry',
        registry_contracts,
        dict(),
        tuple(),
        timeout=poll_timeout,
    )
    registry_address = registry_proxy.address

    # Using 3 * deposit because we assume that is the maximum number of
    # channels that will be created.
    # `total_per_node = channels_per_node * deposit`
    total_per_node = 3 * deposit
    total_asset = total_per_node * len(private_keys)
    asset_addresses = []
    for _ in range(number_of_assets):
        token_proxy = jsonrpc_client.deploy_solidity_contract(
            address,
            'HumanStandardToken',
            humantoken_contracts,
            dict(),
            (total_asset, 'raiden', 2, 'Rd'),
            timeout=poll_timeout,
        )
        asset_address = token_proxy.address
        assert len(asset_address)
        asset_addresses.append(asset_address)

        transaction_hash = registry_proxy.addAsset(asset_address)  # pylint: disable=no-member
        jsonrpc_client.poll(transaction_hash.decode('hex'), timeout=poll_timeout)

        # only the creator of the token starts with a balance, transfer from
        # the creator to the other nodes
        for transfer_to in private_keys:
            if transfer_to != jsonrpc_client.privkey:
                transaction_hash = token_proxy.transfer(  # pylint: disable=no-member
                    privtoaddr(transfer_to),
                    total_per_node,
                    startgas=GAS_LIMIT,
                )
                jsonrpc_client.poll(transaction_hash.decode('hex'))

        for key in private_keys:
            assert token_proxy.balanceOf(privtoaddr(key)) == total_per_node  # pylint: disable=no-member

    raiden_apps = create_sequential_network(
        private_keys,
        asset_addresses[0],
        registry_address,
        channels_per_node,
        deposit,
        settle_timeout,
        poll_timeout,
        transport_class,
        blockchain_service_class,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture(scope='function')
def discovery_blockchain(request, private_keys, geth_cluster, poll_timeout):
    gevent.sleep(2)
    privatekey = private_keys[0]
    address = privtoaddr(privatekey)

    jsonrpc_client = JSONRPCClient(
        host='0.0.0.0',
        privkey=privatekey,
        print_communication=False,
    )
    patch_send_transaction(jsonrpc_client)

    # deploy discovery contract
    discovery_contract_path = get_contract_path('EndpointRegistry.sol')
    discovery_contracts = compile_file(discovery_contract_path, libraries=dict())
    discovery_contract_proxy = jsonrpc_client.deploy_solidity_contract(
        address,
        'EndpointRegistry',
        discovery_contracts,
        dict(),
        tuple(),
        timeout=poll_timeout,
    )
    discovery_contract_address = discovery_contract_proxy.address
    # initialize and return ContractDiscovery object
    from raiden.network.discovery import ContractDiscovery
    return ContractDiscovery(jsonrpc_client, discovery_contract_address), address
