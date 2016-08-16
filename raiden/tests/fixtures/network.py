# -*- coding: utf8 -*-
import gevent
import pytest
from ethereum import slogging
from pyethapp.rpc_client import JSONRPCClient

from ethereum.keys import privtoaddr
from raiden.blockchain.abi import get_contract_path
from raiden.network.discovery import ContractDiscovery
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.network import (
    CHAIN,
    create_network,
    create_sequential_network,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def _raiden_cleanup(request, raiden_apps):
    """ Helper to do cleanup a Raiden App. """
    def _cleanup():
        for app in raiden_apps:
            app.stop()

        # Two tests in sequence could run a UDP server on the same port, a hanging
        # greenlet from the previous tests could send packet to the new server and
        # mess things up. Kill all greenlets to make sure that no left-over state
        # from a previous test interferes with a new one.
        cleanup_tasks()
    request.addfinalizer(_cleanup)


@pytest.fixture
def raiden_chain(request, private_keys, assets_addresses, channels_per_node,
                 deposit, settle_timeout, poll_timeout, blockchain_services,
                 transport_class):
    if len(assets_addresses) > 1:
        raise ValueError('raiden_chain only works with a single asset')

    verbosity = request.config.option.verbose

    raiden_apps = create_sequential_network(
        blockchain_services,
        assets_addresses[0],
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
                   deposit, settle_timeout, poll_timeout, blockchain_services,
                   transport_class):

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
def deployed_network(request, private_keys, asset_addresses, channels_per_node,
                     deposit, settle_timeout, poll_timeout,
                     blockchain_services, transport_class):

    if len(asset_addresses) > 1:
        # currently using create_sequential_network
        raise ValueError('deployed_network only works with one asset')

    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

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
