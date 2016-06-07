""" Utilities to set-up a Raiden network. """
from __future__ import print_function

import copy
import os
import random
from itertools import product
from math import ceil

import gevent
from devp2p.crypto import privtopub
from devp2p.utils import host_port_pubkey_to_uri
from ethereum.keys import privtoaddr, PBKDF2_CONSTANTS
from ethereum.slogging import getLogger
from pyethapp.accounts import mk_privkey, Account
from pyethapp.config import update_config_from_genesis_json
from pyethapp.console_service import Console

from raiden.app import App, INITIAL_PORT
from raiden.network.discovery import PredictiveDiscovery
from raiden.network.rpc.client import BlockChainServiceMock
from raiden.network.transport import UDPTransport
from raiden.utils import sha3

log = getLogger(__name__)  # pylint: disable=invalid-name

DEFAULT_DEPOSIT = 2 ** 240
""" An arbitrary initial balance for each channel in the test network. """


def mk_app(chain, discovery, transport_class, port, host='127.0.0.1'):
    ''' Instantiates an Raiden app with the given configuration. '''
    config = copy.deepcopy(App.default_config)
    config['port'] = port
    config['host'] = host
    config['privkey'] = sha3('{}:{}'.format(host, config['port']))
    return App(config, chain, discovery, transport_class)


def create_network_channels(blockchain_service, assets_list, apps,
                            channels_per_node, deposit=DEFAULT_DEPOSIT):
    """ For each asset create `channel_per_node` channels for each app in `apps`.

    This function will instantiate the requested number of mock contracts
    between the nodes in the network, setting all the channels with `balance`,
    the apps are choosen at random.
    """
    # pylint: disable=too-many-locals
    if channels_per_node > len(apps):
        raise ValueError("Can't create more channels than nodes")

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
    #
    # instead of using complicated logic to handle this cases just sort
    # the apps and use the next n apps to make a channel.
    def sort_by_address(app):
        return app.raiden.address

    def sort_by_channelcount(asset, app):
        addresses = blockchain_service.nettingaddresses_by_asset_participant(
            asset,
            app.raiden.address,
        )

        return len(addresses)

    # Create `channels_per_node` channels for each asset in each app
    for asset_address, curr_app in product(assets_list, sorted(apps, key=sort_by_address)):
        curr_address = curr_app.raiden.address

        contracts_addreses = blockchain_service.nettingaddresses_by_asset_participant(
            asset_address,
            curr_address,
        )

        # get a list of apps that the current node doesn't have a channel with
        other_apps = list(apps)
        other_apps.remove(curr_app)

        for address in contracts_addreses:
            peer_address = blockchain_service.partner(asset_address, address, curr_address)

            for app in other_apps:
                if app.raiden.address == peer_address:
                    other_apps.remove(app)

        # create and initialize the missing channels
        while len(contracts_addreses) < channels_per_node:
            app = sorted(other_apps, key=lambda app: sort_by_channelcount(asset_address, app))[0]  # pylint: disable=cell-var-from-loop
            other_apps.remove(app)

            netcontract_address = blockchain_service.new_netting_contract(
                asset_address,
                app.raiden.address,
                curr_app.raiden.address,
            )
            contracts_addreses.append(netcontract_address)

            for address in [curr_app.raiden.address, app.raiden.address]:
                blockchain_service.deposit(
                    asset_address,
                    netcontract_address,
                    address,
                    deposit,
                )


def create_network(num_nodes=8, num_assets=1, channels_per_node=3, transport_class=None):
    """ Initialize a local test network using the UDP protocol.

    Note:
        The generated network will use two subnets, 127.0.0.10 and 127.0.0.11,
        for this test to work both virtual interfaces must be created prior to
        the test execution::

            ifconfig lo:0 127.0.0.10
            ifconfig lo:1 127.0.0.11
    """
    # pylint: disable=too-many-locals

    # TODO: check if the loopback interfaces exists

    random.seed(1337)

    if channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    client_hosts = ['127.0.0.10', '127.0.0.11']

    # if num_nodes it is not even
    half_of_nodes = int(ceil(num_nodes / 2))

    # globals
    discovery = PredictiveDiscovery((
        (host, half_of_nodes, INITIAL_PORT)
        for host in client_hosts
    ))

    # The mock needs to be atomic since all app's will use the same instance,
    # for the real application the syncronization is done by the JSON-RPC
    # server
    blockchain_service = BlockChainServiceMock()

    # Each app instance is a Node in the network
    apps = []
    for host in client_hosts:
        for idx in range(half_of_nodes):
            port = INITIAL_PORT + idx

            app = mk_app(
                blockchain_service,
                discovery,
                transport_class or UDPTransport,
                port=port,
                host=host,
            )

            apps.append(app)

    for i in range(num_assets):
        asset_address = sha3('asset:%d' % i)[:20]
        blockchain_service.new_channel_manager_contract(asset_address=asset_address)

    asset_list = blockchain_service.asset_addresses
    assert len(asset_list) == num_assets

    create_network_channels(blockchain_service, asset_list, apps, channels_per_node)

    for app in apps:
        for asset_address in asset_list:
            app.raiden.setup_asset(asset_address, app.config['min_locktime'])

    return apps


def create_sequential_network(num_nodes, deposit, asset, transport_class=None):
    """ Create a fully connected network with `num_nodes`, the nodes are
    connect sequentially.

    Returns:
        A list of apps of size `num_nodes`, with the property that every
        sequential pair in the list has an open channel with `deposit` for each
        participant.
    """
    if num_nodes < 2:
        raise ValueError('cannot create a network with less than two nodes')

    host = '127.0.0.10'

    random.seed(42)

    discovery = PredictiveDiscovery((
        (host, num_nodes, INITIAL_PORT),
    ))

    blockchain_service = BlockChainServiceMock()
    blockchain_service.new_channel_manager_contract(asset_address=asset)

    apps = []
    for idx in range(num_nodes):
        port = INITIAL_PORT + idx

        app = mk_app(
            blockchain_service,
            discovery,
            transport_class or UDPTransport,
            port=port,
            host=host,
        )
        apps.append(app)

    for first, second in zip(apps[:-1], apps[1:]):
        netcontract_address = blockchain_service.new_netting_contract(
            asset,
            first.raiden.address,
            second.raiden.address,
        )

        for address in [first.raiden.address, second.raiden.address]:
            blockchain_service.deposit(
                asset,
                netcontract_address,
                address,
                deposit,
            )

    for app in apps:
        app.raiden.setup_asset(asset, app.config['min_locktime'])

    return apps


def hydrachain_network(quantity, base_port, base_datadir):
    """ Initializes a hydrachain network used for testing. """
    # pylint: disable=too-many-locals
    from hydrachain.app import services, start_app, HPCApp
    import pyethapp.config as konfig

    gevent.get_hub().SYSTEM_ERROR = BaseException
    PBKDF2_CONSTANTS['c'] = 100

    def privkey_to_uri(private_key):
        host = b'0.0.0.0'
        pubkey = privtopub(private_key)
        return host_port_pubkey_to_uri(host, base_port, pubkey)

    private_keys = [
        mk_privkey('raidentest:{}'.format(position))
        for position in range(quantity)
    ]

    addresses = [
        privtoaddr(priv)
        for priv in private_keys
    ]

    bootstrap_nodes = [
        privkey_to_uri(private_keys[0]),
    ]

    validator_keys = [
        mk_privkey('raidenvalidator:{}'.format(position))
        for position in range(quantity)
    ]

    validator_addresses = [
        privtoaddr(validator_keys[position])
        for position in range(quantity)
    ]

    alloc = {
        addr.encode('hex'): {
            'balance': '1606938044258990275541962092341162602522202993782792835301376',
        }
        for addr in addresses
    }

    genesis = {
        'nonce': '0x00006d6f7264656e',
        'difficulty': '0x20000',
        'mixhash': '0x00000000000000000000000000000000000000647572616c65787365646c6578',
        'coinbase': '0x0000000000000000000000000000000000000000',
        'timestamp': '0x00',
        'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
        'extraData': '0x',
        'gasLimit': '0x5FEFD8',
        'alloc': alloc,
    }

    all_apps = []
    for number in range(quantity):
        port = base_port + number

        config = konfig.get_default_config(services + [HPCApp])

        # del config['eth']['genesis_hash']
        config = update_config_from_genesis_json(config, genesis)

        datadir = os.path.join(base_datadir, str(number))
        konfig.setup_data_dir(datadir)

        account = Account.new(
            password='',
            key=validator_keys[number],
        )

        config['data_dir'] = datadir
        config['node']['privkey_hex'] = private_keys[number].encode('hex')
        config['hdc']['validators'] = validator_addresses
        config['jsonrpc']['listen_port'] += number
        config['client_version_string'] = 'NODE{}'.format(number)

        # setting to 0 so that the CALLCODE opcode works at the start of the
        # network
        config['eth']['block']['HOMESTEAD_FORK_BLKNUM'] = 0

        config['discovery']['bootstrap_nodes'] = bootstrap_nodes
        config['discovery']['listen_port'] = port

        config['p2p']['listen_port'] = port
        config['p2p']['min_peers'] = min(10, quantity - 1)
        config['p2p']['max_peers'] = quantity * 2

        # only one of the nodes should have the Console service running
        if number != 0:
            config['deactivated_services'].append(Console.name)

        hydrachain_app = start_app(config, accounts=[account])
        all_apps.append(hydrachain_app)

    return private_keys, all_apps
