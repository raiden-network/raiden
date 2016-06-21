""" Utilities to set-up a Raiden network. """
from __future__ import print_function

import copy
import os
import random
from itertools import product
from math import floor

from devp2p.crypto import privtopub
from devp2p.utils import host_port_pubkey_to_uri
from ethereum.keys import privtoaddr
from ethereum.slogging import getLogger
from pyethapp.accounts import Account
from pyethapp.config import update_config_from_genesis_json
from pyethapp.console_service import Console
from pyethapp.rpc_client import JSONRPCClient

from raiden.app import App, INITIAL_PORT
from raiden.network.discovery import Discovery
from raiden.network.rpc.client import BlockChainServiceMock, GAS_LIMIT_HEX

log = getLogger(__name__)  # pylint: disable=invalid-name

DEFAULT_DEPOSIT = 2 ** 240
""" An arbitrary initial balance for each channel in the test network. """


def check_channel(app1, app2, asset_address, netcontract_address, deposit):
    assert app1.raiden.chain.isopen(asset_address, netcontract_address)
    assert app2.raiden.chain.isopen(asset_address, netcontract_address)

    app1_details = app1.raiden.chain.netting_contract_detail(
        asset_address,
        netcontract_address,
        app1.raiden.address,
    )

    app2_details = app1.raiden.chain.netting_contract_detail(
        asset_address,
        netcontract_address,
        app2.raiden.address,
    )

    assert app1_details['our_balance'] == app2_details['partner_balance'] == deposit
    assert app1_details['partner_balance'] == app2_details['our_balance'] == deposit


def create_app(privkey_bin, chain, discovery, transport_class, port, host='127.0.0.1'):  # pylint: disable=too-many-arguments
    ''' Instantiates an Raiden app with the given configuration. '''
    config = copy.deepcopy(App.default_config)

    config['port'] = port
    config['host'] = host
    config['privkey'] = privkey_bin

    return App(
        config,
        chain,
        discovery,
        transport_class,
    )


def create_network_channels(assets_list, apps, channels_per_node, deposit, settle_timeout):
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
        addresses = app.raiden.chain.nettingaddresses_by_asset_participant(
            asset,
            app.raiden.address,
        )

        return len(addresses)

    # Create `channels_per_node` channels for each asset in each app
    for asset_address, curr_app in product(assets_list, sorted(apps, key=sort_by_address)):
        blockchain_service = curr_app.raiden.chain
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
                curr_app.raiden.address,
                app.raiden.address,
                settle_timeout,
            )
            contracts_addreses.append(netcontract_address)

            for app in [curr_app, app]:
                # use each app's own chain because of the private key / local
                # signing
                app.raiden.chain.asset_approve(
                    asset_address,
                    netcontract_address,
                    deposit,
                )

                app.raiden.chain.deposit(
                    asset_address,
                    netcontract_address,
                    app.raiden.address,
                    deposit,
                )

            check_channel(
                curr_app,
                app,
                asset_address,
                netcontract_address,
                deposit,
            )


def create_network(private_keys, assets_addresses, registry_address,  # pylint: disable=too-many-arguments
                   channels_per_node, deposit, settle_timeout, transport_class,
                   blockchain_service_class):
    """ Initialize a local test network using the UDP protocol.

    Note:
        The generated network will use two subnets, 127.0.0.10 and 127.0.0.11,
        for this test to work both virtual interfaces must be created prior to
        the test execution::

            ifconfig lo:0 127.0.0.10
            ifconfig lo:1 127.0.0.11
    """
    # pylint: disable=too-many-locals

    random.seed(1337)
    num_nodes = len(private_keys)

    if channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    # if num_nodes it is not even
    half_of_nodes = int(floor(len(private_keys) / 2))

    # globals
    discovery = Discovery()

    # The mock needs to be atomic since all app's will use the same instance,
    # for the real application the syncronization is done by the JSON-RPC
    # server
    blockchain_service_class = blockchain_service_class or BlockChainServiceMock

    # Each app instance is a Node in the network
    apps = []
    for idx, privatekey_bin in enumerate(private_keys):

        # TODO: check if the loopback interfaces exists
        # split the nodes into two different networks
        if idx > half_of_nodes:
            host = '127.0.0.11'
        else:
            host = '127.0.0.10'

        nodeid = privtoaddr(privatekey_bin)
        port = INITIAL_PORT + idx

        discovery.register(nodeid, host, port)

        jsonrpc_client = JSONRPCClient(
            privkey=privatekey_bin,
            print_communication=False,
        )
        blockchain_service = blockchain_service_class(
            jsonrpc_client,
            registry_address,
        )

        app = create_app(
            privatekey_bin,
            blockchain_service,
            discovery,
            transport_class,
            port=port,
            host=host,
        )

        apps.append(app)

    create_network_channels(
        assets_addresses,
        apps,
        channels_per_node,
        deposit,
        settle_timeout,
    )

    for app in apps:
        for asset in assets_addresses:
            app.raiden.setup_asset(asset, app.config['reveal_timeout'])

    return apps


def create_sequential_network(private_keys, asset_address, registry_address,  # pylint: disable=too-many-arguments
                              deposit, settle_timeout, transport_class,
                              blockchain_service_class):
    """ Create a fully connected network with `num_nodes`, the nodes are
    connect sequentially.

    Returns:
        A list of apps of size `num_nodes`, with the property that every
        sequential pair in the list has an open channel with `deposit` for each
        participant.
    """
    # pylint: disable=too-many-locals

    random.seed(42)

    host = '127.0.0.10'
    num_nodes = len(private_keys)

    if num_nodes < 2:
        raise ValueError('cannot create a network with less than two nodes')

    discovery = Discovery()
    blockchain_service_class = blockchain_service_class or BlockChainServiceMock

    apps = []
    for idx, privatekey_bin in enumerate(private_keys):
        port = INITIAL_PORT + idx
        nodeid = privtoaddr(privatekey_bin)

        discovery.register(nodeid, host, port)

        jsonrpc_client = JSONRPCClient(
            privkey=privatekey_bin,
            print_communication=False,
        )
        blockchain_service = blockchain_service_class(
            jsonrpc_client,
            registry_address,
        )

        app = create_app(
            privatekey_bin,
            blockchain_service,
            discovery,
            transport_class,
            port=port,
            host=host,
        )
        apps.append(app)

    for first, second in zip(apps[:-1], apps[1:]):
        netcontract_address = first.raiden.chain.new_netting_contract(
            asset_address,
            first.raiden.address,
            second.raiden.address,
            settle_timeout,
        )

        for app in [first, second]:
            # use each app's own chain because of the private key / local
            # signing
            app.raiden.chain.asset_approve(
                asset_address,
                netcontract_address,
                deposit,
            )

            app.raiden.chain.deposit(
                asset_address,
                netcontract_address,
                app.raiden.address,
                deposit,
            )

        check_channel(
            first,
            second,
            asset_address,
            netcontract_address,
            deposit,
        )

    for app in apps:
        app.raiden.setup_asset(asset_address, app.config['reveal_timeout'])

    return apps


def create_hydrachain_network(private_keys, hydrachain_private_keys, p2p_base_port, base_datadir):
    """ Initializes a hydrachain network used for testing. """
    # pylint: disable=too-many-locals
    from hydrachain.app import services, start_app, HPCApp
    import pyethapp.config as konfig

    def privkey_to_uri(private_key):
        host = b'0.0.0.0'
        pubkey = privtopub(private_key)
        return host_port_pubkey_to_uri(host, p2p_base_port, pubkey)

    account_addresses = [
        privtoaddr(priv)
        for priv in private_keys
    ]

    alloc = {
        address.encode('hex'): {
            'balance': '1606938044258990275541962092341162602522202993782792835301376',
        }
        for address in account_addresses
    }

    genesis = {
        'nonce': '0x00006d6f7264656e',
        'difficulty': '0x20000',
        'mixhash': '0x00000000000000000000000000000000000000647572616c65787365646c6578',
        'coinbase': '0x0000000000000000000000000000000000000000',
        'timestamp': '0x00',
        'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
        'extraData': '0x',
        'gasLimit': GAS_LIMIT_HEX,
        'alloc': alloc,
    }

    bootstrap_nodes = [
        privkey_to_uri(hydrachain_private_keys[0]),
    ]

    validators_addresses = [
        privtoaddr(private_key)
        for private_key in hydrachain_private_keys
    ]

    all_apps = []
    for number, private_key in enumerate(hydrachain_private_keys):
        config = konfig.get_default_config(services + [HPCApp])
        config = update_config_from_genesis_json(config, genesis)

        datadir = os.path.join(base_datadir, str(number))
        konfig.setup_data_dir(datadir)

        account = Account.new(
            password='',
            key=private_key,
        )

        config['data_dir'] = datadir
        config['hdc']['validators'] = validators_addresses
        config['node']['privkey_hex'] = private_key.encode('hex')
        config['jsonrpc']['listen_port'] += number
        config['client_version_string'] = 'NODE{}'.format(number)

        # setting to 0 so that the CALLCODE opcode works at the start of the
        # network
        config['eth']['block']['HOMESTEAD_FORK_BLKNUM'] = 0

        config['discovery']['bootstrap_nodes'] = bootstrap_nodes
        config['discovery']['listen_port'] = p2p_base_port + number

        config['p2p']['listen_port'] = p2p_base_port + number
        config['p2p']['min_peers'] = min(10, len(hydrachain_private_keys) - 1)
        config['p2p']['max_peers'] = len(hydrachain_private_keys) * 2

        # only one of the nodes should have the Console service running
        if number != 0 and Console.name not in config['deactivated_services']:
            config['deactivated_services'].append(Console.name)

        hydrachain_app = start_app(config, accounts=[account])
        all_apps.append(hydrachain_app)

    return all_apps
