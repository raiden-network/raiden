# -*- coding: utf8 -*-
import pytest
from ethereum import slogging
from pyethapp.rpc_client import JSONRPCClient

from ethereum.keys import privtoaddr
from raiden.blockchain import get_contract_path
from raiden.network.rpc.client import GAS_LIMIT
from raiden.tests.utils.network import (
    create_network,
    create_sequential_network,
    CHAIN,
)
from raiden.network.discovery import ContractDiscovery
from raiden.network.transport import UDPTransport
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

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def _raiden_cleanup(request, raiden_apps):
    """ Helper to do cleanup a Raiden App.

    Two tests in sequence could run a UDP server on the same port, a hanging
    greenlet from the previous tests could send packet to the new server and
    mess things up. Kill all greenlets to make sure that no left-over state
    from a previous test interferes with a new one.
    """
    def _cleanup():
        for app in raiden_apps:
            app.stop()

        # kill all leftover tasklets
        cleanup_tasks()
    request.addfinalizer(_cleanup)


@pytest.fixture
def transport_class():
    return UDPTransport


@pytest.fixture
def network_channels_per_node():
    """ Number of channels per Raiden node in for the  """
    return 1


@pytest.fixture
def raiden_chain(request, private_keys, asset, channels_per_node, deposit,
                 settle_timeout, poll_timeout, registry_address, blockchain_service,
                 transport_class):
    verbosity = request.config.option.verbose

    raiden_apps = create_sequential_network(
        blockchain_services,
        asset,
        channels_per_node,
        deposit,
        settle_timeout,
        transport_class,
        verbosity,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture
def raiden_network(request, private_keys, assets_addresses, channels_per_node,
                   deposit, settle_timeout, poll_timeout, registry_address,
                   blockchain_services, transport_class):

    chain = blockchain_services[0]
    registry = chain.registry(registry_address)
    for asset in assets_addresses:
        registry.add_asset(asset)

    verbosity = request.config.option.verbose

    raiden_apps = create_network(
        blockchain_services,
        assets_addresses,
        channels_per_node,
        deposit,
        settle_timeout,
        transport_class,
        verbosity,
    )

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture
def deployed_network(request, private_keys, channels_per_node, deposit,
                     number_of_assets, settle_timeout, poll_timeout,
                     transport_class, cluster):

    if number_of_assets:
        # currently using create_sequential_network that work only on one asset
        raise ValueError('fixture needs fixing to use morethan one asset.')

    gevent.sleep(2)
    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

    privatekey = private_keys[0]
    address = privtoaddr(privatekey)

    humantoken_path = get_contract_path('HumanStandardToken.sol')

    humantoken_contracts = compile_file(humantoken_path, libraries=dict())

    # `total_per_node = channels_per_node * deposit`
    # assuming 3 is the maximum number of channels used.
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
        blockchain_services,
        asset_addresses[0],
        channels_per_node,
        deposit,
        settle_timeout,
        transport_class,
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
    discovery = ContractDiscovery(
        jsonrpc_client,
        discovery_contract_address,
    )

    return (discovery, address)
