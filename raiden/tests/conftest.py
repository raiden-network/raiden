# -*- coding: utf8 -*-
import pytest
import gevent
import gevent.monkey
from ethereum import slogging, tester
from ethereum.keys import privtoaddr, PBKDF2_CONSTANTS
from ethereum._solidity import compile_file
from ethereum.tester import ABIContract, ContractTranslator
from pyethapp.rpc_client import JSONRPCClient

from raiden.utils import sha3
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.mock_client import BlockChainServiceMock, MOCK_REGISTRY_ADDRESS
from raiden.tests.utils.tester_client import BlockChainServiceTesterMock
from raiden.network.transport import UDPTransport
from raiden.network.rpc.client import (
    patch_send_transaction,
    BlockChainService,
    DEFAULT_POLL_TIMEOUT,
    GAS_LIMIT,
)
from raiden.blockchain.abi import get_contract_path
from raiden.raiden_service import DEFAULT_SETTLE_TIMEOUT
from raiden.tests.utils.network import (
    create_network,
    create_sequential_network,
    create_hydrachain_cluster,
    create_tester_sequential_network,
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
log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def _raiden_cleanup(request, raiden_apps):
    """ Helper to do proper cleanup.

    Two tests in sequence could run on the a UDP server on the same port, a
    hanging greenlet from the previous tests could send packet to the new test
    messing things up. Kill all greenlets to make sure that no left-over state
    from a previous test interferes with a new one.
    """
    def _cleanup():
        for app in raiden_apps:
            app.stop()

        # kill all leftover tasklets
        cleanup_tasks()
    request.addfinalizer(_cleanup)


def _hydrachain_cluster(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    """ Helper to do proper cleanup. """
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


def _geth_cluster(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    """ Helper to do proper cleanup. """
    verbosity = request.config.option.verbose

    geth_processes = create_geth_cluster(
        private_keys,
        cluster_private_keys,
        p2p_base_port,
        str(tmpdir),
        verbosity,
    )

    def _cleanup():
        for process in geth_processes:
            process.terminate()

        # Then kill any remaining tasklet
        cleanup_tasks()

    request.addfinalizer(_cleanup)
    return geth_processes


def pytest_addoption(parser):
    # hydrachain is a faster but unstable option, by default we use geth
    parser.addoption(
        '--cluster-type',
        choices=['hydrachain', 'geth'],
        default='geth',
    )

    # useful to configure raiden's logging and hydrachain if (--cluster-type is
    # hydrachain, note that some times the configuration fail with hydrachain
    # because a pyethapp/ethereum module could have it's root logger configure
    # before)
    parser.addoption(
        '--log-config',
        default=None,
    )


@pytest.fixture(autouse=True)
def logging_level(request):
    """ Set ups the test logging level.

    For integration tests this also sets the geth verbosity.
    """
    if request.config.option.log_config is not None:
        slogging.configure(request.config.option.log_config)
        return

    if request.config.option.verbose > 0:
        slogging.configure(':DEBUG')


@pytest.fixture(scope='session', autouse=True)
def enable_greenlet_debugger(request):
    if request.config.option.usepdb:
        from pyethapp.utils import enable_greenlet_debugger
        enable_greenlet_debugger()


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
def asset_amount():
    return 10000


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
def cluster(request, private_keys, cluster_private_keys, p2p_base_port, tmpdir):
    cluster_type = request.config.option.cluster_type

    if cluster_type == 'geth':
        return _geth_cluster(
            request,
            private_keys,
            cluster_private_keys,
            p2p_base_port,
            tmpdir,
        )

    if cluster_type == 'hydrachain':
        return _hydrachain_cluster(
            request,
            private_keys,
            cluster_private_keys,
            p2p_base_port,
            tmpdir,
        )

    # check pytest_addoption
    raise ValueError('unknow cluster type {}'.format(cluster_type))


@pytest.fixture
def asset():
    """ Raiden chain asset. """
    return sha3('asset')[:20]


@pytest.fixture
def deposit():
    """ Raiden chain default deposit. """
    return DEFAULT_DEPOSIT


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
    verbosity = request.config.option.verbose

    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceMock(
            privkey,
            MOCK_REGISTRY_ADDRESS,
        )

        blockchain_services.append(blockchain)

    raiden_apps = create_sequential_network(
        blockchain_services,
        asset,
        registry_address,
        channels_per_node,
        deposit,
        settle_timeout,
        poll_timeout,
        transport_class,
        verbosity,
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

    verbosity = request.config.option.verbose

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
        verbosity,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture
def deployed_network(request, private_keys, channels_per_node, deposit,
                     number_of_assets, settle_timeout, poll_timeout,
                     transport_class, cluster):

    gevent.sleep(2)
    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

    privatekey = private_keys[0]
    address = privtoaddr(privatekey)
    blockchain_service_class = BlockChainService

    print_communication = False
    if request.config.option.verbose > 7:
        print_communication = True

    jsonrpc_client = JSONRPCClient(
        host='0.0.0.0',
        privkey=privatekey,
        print_communication=print_communication,
    )
    patch_send_transaction(jsonrpc_client)

    humantoken_path = get_contract_path('HumanStandardToken.sol')
    registry_path = get_contract_path('Registry.sol')

    humantoken_contracts = compile_file(humantoken_path, libraries=dict())
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

    # Using 3 * deposit because we assume that is the maximum number of
    # channels that will be created.
    # `total_per_node = channels_per_node * deposit`
    total_per_node = 3 * deposit
    total_asset = total_per_node * len(private_keys)
    asset_addresses = []
    for _ in range(number_of_assets):
        log.info('Deploying one Token contract')
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

    verbosity = request.config.option.verbose

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
        verbosity,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture
def discovery_blockchain(request, private_keys, cluster, poll_timeout):
    gevent.sleep(2)
    privatekey = private_keys[0]
    address = privtoaddr(privatekey)

    print_communication = False
    if request.config.option.verbose > 7:
        print_communication = True

    jsonrpc_client = JSONRPCClient(
        host='0.0.0.0',
        privkey=privatekey,
        print_communication=print_communication,
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


@pytest.fixture(scope='session')
def token_abi():
    human_token_path = get_contract_path('HumanStandardToken.sol')
    human_token_compiled = compile_file(human_token_path, combined='abi')
    human_token_abi = human_token_compiled['HumanStandardToken']['abi']
    return human_token_abi


@pytest.fixture(scope='session')
def channel_manager_abi():
    channel_manager_path = get_contract_path('ChannelManagerContract.sol')
    channel_manager_compiled = compile_file(channel_manager_path, combined='abi')
    channel_manager_abi = channel_manager_compiled['ChannelManagerContract']['abi']
    return channel_manager_abi


@pytest.fixture(scope='session')
def netting_channel_abi():
    netting_channel_path = get_contract_path('NettingChannelContract.sol')
    netting_channel_compiled = compile_file(netting_channel_path, combined='abi')
    netting_channel_abi = netting_channel_compiled['NettingChannelContract']['abi']
    return netting_channel_abi


@pytest.fixture(scope='session')
def registry_abi():
    registry_path = get_contract_path('Registry.sol')
    registry_compiled = compile_file(registry_path, combined='abi')
    registry_abi = registry_compiled['Registry']['abi']
    return registry_abi


@pytest.fixture
def tester_state():
    state = tester.state()
    state.block.number = 1150001  # HOMESTEAD_FORK_BLKNUM=1150000
    return state


@pytest.fixture
def tester_events():
    events = []
    return events


@pytest.fixture
def tester_token_address(asset_amount, tester_state):
    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    standard_token_address = tester_state.contract(
        None,
        path=standard_token_path,
        language='solidity',
    )

    human_token_libraries = {
        'StandardToken': standard_token_address.encode('hex'),
    }
    human_token_proxy = tester_state.abi_contract(  # using abi_contract because of the constructor_parameters
        None,
        path=human_token_path,
        language='solidity',
        libraries=human_token_libraries,
        constructor_parameters=[asset_amount, 'raiden', 0, 'rd'],
    )

    tester_state.mine()

    human_token_address = human_token_proxy.address
    return human_token_address


@pytest.fixture
def tester_nettingchannel_library_address(tester_state):
    netting_library_path = get_contract_path('NettingChannelLibrary.sol')
    library_address = tester_state.contract(
        None,
        path=netting_library_path,
        language='solidity',
        contract_name='NettingChannelLibrary',
    )
    return library_address


@pytest.fixture
def tester_channelmanager_library_address(tester_state, tester_nettingchannel_library_address):
    channelmanager_library_path = get_contract_path('ChannelManagerLibrary.sol')
    manager_address = tester_state.contract(
        None,
        path=channelmanager_library_path,
        language='solidity',
        contract_name='ChannelManagerLibrary',
        libraries={
            'NettingChannelLibrary': tester_nettingchannel_library_address.encode('hex'),
        }
    )
    return manager_address


@pytest.fixture
def tester_registry_address(tester_state, tester_channelmanager_library_address):
    registry_path = get_contract_path('Registry.sol')
    registry_address = tester_state.contract(
        None,
        path=registry_path,
        language='solidity',
        contract_name='Registry',
        libraries={
            'ChannelManagerLibrary': tester_channelmanager_library_address.encode('hex')
        }
    )
    return registry_address


@pytest.fixture
def tester_token(tester_state, tester_token_address, token_abi, tester_events):
    translator = ContractTranslator(token_abi)

    return ABIContract(
        tester_state,
        translator,
        tester_token_address,
        log_listener=tester_events.append,
    )


@pytest.fixture
def tester_registry(tester_state, registry_abi, tester_registry_address, tester_events):
    translator = ContractTranslator(registry_abi)

    return ABIContract(
        tester_state,
        translator,
        tester_registry_address,
        log_listener=tester_events.append,
    )


@pytest.fixture
def tester_default_channel_manager(tester_state, tester_token, tester_registry,
                                   tester_events, channel_manager_abi):
    contract_address = tester_registry.addAsset(tester_token.address)
    translator = ContractTranslator(channel_manager_abi)
    channel_manager_abi = ABIContract(
        tester_state,
        translator,
        contract_address,
        log_listener=tester_events.append,
    )
    return channel_manager_abi


def tester_chain(request, tester_state, tester_registry, private_keys, asset,
                 channels_per_node, deposit, settle_timeout):

    blockchain_service_class = BlockChainServiceTesterMock
    verbosity = request.config.option.verbose

    raiden_apps = create_tester_sequential_network(
        private_keys,
        asset,
        registry_address,
        channels_per_node,
        deposit,
        settle_timeout,
        poll_timeout,
        transport_class,
        blockchain_service_class,
        verbosity,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps
