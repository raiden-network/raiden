""" Utilities to set-up a Raiden network. """
from binascii import hexlify
from collections import namedtuple
from os import environ

import gevent
from gevent import server
import structlog
from eth_utils import decode_hex
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY

from raiden import waiting
from raiden.app import App
from raiden.network.blockchain_service import BlockChainService
from raiden.network.matrixtransport import MatrixTransport
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.throttle import TokenBucket
from raiden.network.transport.udp.udp_transport import UDPTransport
from raiden.settings import DEFAULT_RETRY_TIMEOUT
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.utils import (
    get_contract_path,
    privatekey_to_address,
)
from raiden.utils.solc import compile_files_cwd

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

CHAIN = object()  # Flag used by create a network does make a loop with the channels
BlockchainServices = namedtuple(
    'BlockchainServices',
    (
        'deploy_registry',
        'secret_registry',
        'deploy_service',
        'blockchain_services',
    ),
)


def check_channel(app1, app2, netting_channel_address, settle_timeout, deposit_amount):
    netcontract1 = app1.raiden.chain.netting_channel(netting_channel_address)
    netcontract2 = app2.raiden.chain.netting_channel(netting_channel_address)

    # Check a valid settle timeout was used, the netting contract has an
    # enforced minimum and maximum
    assert settle_timeout == netcontract1.settle_timeout()
    assert settle_timeout == netcontract2.settle_timeout()

    if deposit_amount > 0:
        assert netcontract1.can_transfer()
        assert netcontract2.can_transfer()

    app1_details = netcontract1.detail()
    app2_details = netcontract2.detail()

    assert app1_details['our_address'] == app2_details['partner_address']
    assert app1_details['partner_address'] == app2_details['our_address']

    assert app1_details['our_balance'] == app2_details['partner_balance']
    assert app1_details['partner_balance'] == app2_details['our_balance']

    assert app1_details['our_balance'] == deposit_amount
    assert app1_details['partner_balance'] == deposit_amount
    assert app2_details['our_balance'] == deposit_amount
    assert app2_details['partner_balance'] == deposit_amount


def netting_channel_open_and_deposit(app0, app1, token_address, deposit, settle_timeout):
    """ Open a new channel with app0 and app1 as participants """
    assert token_address

    manager = app0.raiden.default_registry.manager_by_token(token_address)
    netcontract_address = manager.new_netting_channel(
        app1.raiden.address,
        settle_timeout,
    )
    assert netcontract_address

    for app in [app0, app1]:
        # Use each app's own chain because of the private key / local signing
        token = app.raiden.chain.token(token_address)
        netting_channel = app.raiden.chain.netting_channel(netcontract_address)

        # This check can succeed and the deposit still fail, if channels are
        # openned in parallel
        previous_balance = token.balance_of(app.raiden.address)
        assert previous_balance >= deposit

        token.approve(netcontract_address, deposit)
        netting_channel.set_total_deposit(deposit)

        # Balance must decrease by at least but not exactly `deposit` amount,
        # because channels can be openned in parallel
        new_balance = token.balance_of(app.raiden.address)
        assert new_balance <= previous_balance - deposit

    check_channel(
        app0,
        app1,
        netcontract_address,
        settle_timeout,
        deposit,
    )


def network_with_minimum_channels(apps, channels_per_node):
    """ Return the channels that should be created so that each app has at
    least `channels_per_node` with the other apps.

    Yields a two-tuple (app1, app2) that must be connected to respect
    `channels_per_node`. Any preexisting channels will be ignored, so the nodes
    might end up with more channels open than `channels_per_node`.
    """
    # pylint: disable=too-many-locals
    if channels_per_node > len(apps):
        raise ValueError("Can't create more channels than nodes")

    if len(apps) == 1:
        raise ValueError("Can't create channels with only one node")

    # If we use random nodes we can hit some edge cases, like the
    # following:
    #
    #  node | #channels
    #   A   |    0
    #   B   |    1  D-B
    #   C   |    1  D-C
    #   D   |    2  D-C D-B
    #
    # B and C have one channel each, and they do not a channel
    # between them, if in this iteration either app is the current
    # one and random choose the other to connect, A will be left
    # with no channels. In this scenario we need to force the use
    # of the node with the least number of channels.

    unconnected_apps = dict()
    channel_count = dict()

    # assume that the apps don't have any connection among them
    for curr_app in apps:
        all_apps = list(apps)
        all_apps.remove(curr_app)
        unconnected_apps[curr_app.raiden.address] = all_apps
        channel_count[curr_app.raiden.address] = 0

    # Create `channels_per_node` channels for each token in each app
    # for token_address, curr_app in product(tokens_list, sorted(apps, key=sort_by_address)):

    # sorting the apps and use the next n apps to make a channel to avoid edge
    # cases
    for curr_app in sorted(apps, key=lambda app: app.raiden.address):
        available_apps = unconnected_apps[curr_app.raiden.address]

        while channel_count[curr_app.raiden.address] < channels_per_node:
            least_connect = sorted(
                available_apps,
                key=lambda app: channel_count[app.raiden.address],
            )[0]

            channel_count[curr_app.raiden.address] += 1
            available_apps.remove(least_connect)

            channel_count[least_connect.raiden.address] += 1
            unconnected_apps[least_connect.raiden.address].remove(curr_app)

            yield curr_app, least_connect


def create_network_channels(raiden_apps, channels_per_node):
    num_nodes = len(raiden_apps)

    if channels_per_node is not CHAIN and channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    if channels_per_node == 0:
        app_channels = []
    elif channels_per_node == CHAIN:
        app_channels = list(zip(raiden_apps[:-1], raiden_apps[1:]))
    else:
        app_channels = list(network_with_minimum_channels(raiden_apps, channels_per_node))

    return app_channels


def create_sequential_channels(raiden_apps, channels_per_node):
    """ Create a fully connected network with `num_nodes`, the nodes are
    connect sequentially.

    Returns:
        A list of apps of size `num_nodes`, with the property that every
        sequential pair in the list has an open channel with `deposit` for each
        participant.
    """

    num_nodes = len(raiden_apps)

    if num_nodes < 2:
        raise ValueError('cannot create a network with less than two nodes')

    if channels_per_node not in (0, 1, 2, CHAIN):
        raise ValueError('can only create networks with 0, 1, 2 or CHAIN channels')

    if channels_per_node == 0:
        app_channels = list()

    if channels_per_node == 1:
        assert len(raiden_apps) % 2 == 0, 'needs an even number of nodes'
        every_two = iter(raiden_apps)
        app_channels = list(zip(every_two, every_two))

    if channels_per_node == 2:
        app_channels = list(zip(raiden_apps, raiden_apps[1:] + [raiden_apps[0]]))

    if channels_per_node == CHAIN:
        app_channels = list(zip(raiden_apps[:-1], raiden_apps[1:]))

    return app_channels


def create_apps(
        blockchain_services,
        endpoint_discovery_services,
        registry_address,
        secret_registry_address,
        raiden_udp_ports,
        reveal_timeout,
        settle_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        local_matrix_url=None,
):
    """ Create the apps."""
    # pylint: disable=too-many-locals
    services = zip(blockchain_services, endpoint_discovery_services)

    apps = []
    for idx, (blockchain, discovery) in enumerate(services):
        port = raiden_udp_ports[idx]
        private_key = blockchain.private_key
        nodeid = privatekey_to_address(private_key)

        host = '127.0.0.1'

        discovery.register(nodeid, host, port)

        config = {
            'host': host,
            'port': port,
            'external_ip': host,
            'external_port': port,
            'privatekey_hex': hexlify(private_key),
            'reveal_timeout': reveal_timeout,
            'settle_timeout': settle_timeout,
            'database_path': database_paths[idx],
            'transport': {
                'retry_interval': retry_interval,
                'retries_before_backoff': retries_before_backoff,
                'throttle_capacity': throttle_capacity,
                'throttle_fill_rate': throttle_fill_rate,
                'nat_invitation_timeout': nat_invitation_timeout,
                'nat_keepalive_retries': nat_keepalive_retries,
                'nat_keepalive_timeout': nat_keepalive_timeout,
            },
            'rpc': True,
            'console': False,
        }

        use_matrix = local_matrix_url is not None
        if use_matrix:
            config.update({
                'transport_type': 'matrix',
                'matrix': {
                    'server': local_matrix_url,
                    'server_name': 'matrix.local.raiden',
                    'discovery_room': {
                        'alias_fragment': 'discovery',
                        'server': 'matrix.local.raiden',
                    },
                },
            })
            if 'TRAVIS' in environ:
                config.update({'login_retry_wait': 1.5})

        config_copy = App.DEFAULT_CONFIG.copy()
        config_copy.update(config)

        registry = blockchain.registry(registry_address)
        secret_registry = blockchain.secret_registry(secret_registry_address)

        if use_matrix:
            transport = MatrixTransport(config['matrix'])
        else:
            throttle_policy = TokenBucket(
                config['transport']['throttle_capacity'],
                config['transport']['throttle_fill_rate'],
            )

            transport = UDPTransport(
                discovery,
                server._udp_socket((host, port)),  # pylint: disable=protected-access
                throttle_policy,
                config['transport'],
            )

        app = App(
            config_copy,
            blockchain,
            registry,
            secret_registry,
            transport,
            discovery,
        )
        apps.append(app)

    return apps


def jsonrpc_services(
        deploy_key,
        deploy_client,
        private_keys,
        web3=None,
):
    deploy_blockchain = BlockChainService(deploy_key, deploy_client)

    secret_registry_address = deploy_contract_web3(
        CONTRACT_SECRET_REGISTRY,
        deploy_client,
    )
    secret_registry = deploy_blockchain.secret_registry(secret_registry_address)  # noqa

    registry_path = get_contract_path('Registry.sol')
    registry_contracts = compile_files_cwd([registry_path])

    log.info('Deploying registry contract')
    registry_proxy = deploy_client.deploy_solidity_contract(
        'Registry',
        registry_contracts,
        dict(),
        tuple(),
        contract_path=registry_path,
    )
    registry_address = decode_hex(registry_proxy.contract.address)

    # at this point the blockchain must be running, this will overwrite the
    # method so even if the client is patched twice, it should work fine

    deploy_registry = deploy_blockchain.registry(registry_address)

    host = '0.0.0.0'
    blockchain_services = list()
    for privkey in private_keys:
        rpc_client = JSONRPCClient(
            host,
            deploy_client.port,
            privkey,
            web3=web3,
        )

        blockchain = BlockChainService(privkey, rpc_client)
        blockchain_services.append(blockchain)

    return BlockchainServices(
        deploy_registry,
        secret_registry,
        deploy_blockchain,
        blockchain_services,
    )


def wait_for_alarm_start(raiden_apps, retry_timeout=DEFAULT_RETRY_TIMEOUT):
    """Wait until all Alarm tasks start & set up the last_block"""
    apps = list(raiden_apps)

    while apps:
        app = apps[-1]

        if app.raiden.alarm.last_block_number is None:
            gevent.sleep(retry_timeout)
        else:
            apps.pop()


def wait_for_usable_channel(
        app0,
        app1,
        registry_address,
        token_address,
        our_deposit,
        partner_deposit,
        retry_timeout=DEFAULT_RETRY_TIMEOUT,
):
    """ Wait until the channel from app0 to app1 is usable.

    The channel and the deposits are registered, and the partner network state
    is reachable.
    """
    waiting.wait_for_newchannel(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        retry_timeout,
    )

    waiting.wait_for_participant_newbalance(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        app0.raiden.address,
        our_deposit,
        retry_timeout,
    )

    waiting.wait_for_participant_newbalance(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        app1.raiden.address,
        partner_deposit,
        retry_timeout,
    )

    waiting.wait_for_healthy(
        app0.raiden,
        app1.raiden.address,
        retry_timeout,
    )


def wait_for_channels(
        app_channels,
        registry_address,
        token_addresses,
        deposit,
        retry_timeout=DEFAULT_RETRY_TIMEOUT,
):
    """ Wait until all channels are usable from both directions. """
    for app0, app1 in app_channels:
        for token_address in token_addresses:
            wait_for_usable_channel(
                app0,
                app1,
                registry_address,
                token_address,
                deposit,
                deposit,
                retry_timeout,
            )
            wait_for_usable_channel(
                app1,
                app0,
                registry_address,
                token_address,
                deposit,
                deposit,
                retry_timeout,
            )
