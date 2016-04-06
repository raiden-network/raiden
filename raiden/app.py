# -*- coding: utf8 -*-
from __future__ import print_function

import copy
import random
from itertools import product
from math import ceil
from ethereum import slogging

from raiden.raiden_service import RaidenService
from raiden.network.transport import DummyTransport, UDPTransport
from raiden.network.discovery import PredictiveDiscovery
from raiden.network.rpc.client import BlockChainServiceMock
from raiden.utils import sha3, pex

log = slogging.get_logger('raiden.app')  # pylint: disable=invalid-name


INITIAL_PORT = 40001
DEFAULT_DEPOSIT = 2 ** 240
""" An arbitrary initial balance for each channel in the test network. """


class App(object):  # pylint: disable=too-few-public-methods
    default_config = dict(host='', port=INITIAL_PORT, privkey='')

    def __init__(self, config, chain, discovery, transport_class=DummyTransport):
        self.config = config
        self.transport = transport_class(config['host'], config['port'])
        self.raiden = RaidenService(chain, config['privkey'], self.transport, discovery)
        discovery.register(self.raiden.address, self.transport.host, self.transport.port)
        self.discovery = discovery


def mk_app(chain, discovery, transport_class, port, host='127.0.0.1'):
    ''' Instantiates an Raiden app with the given configuration. '''
    config = copy.deepcopy(App.default_config)
    config['port'] = port
    config['host'] = host
    config['privkey'] = sha3("{}:{}".format(host, config['port']))
    return App(config, chain, discovery, transport_class)


def print_channel_count(chain_service, asset, apps):
    count = dict()

    for node in apps:
        address = node.raiden.address
        addresses = chain_service.nettingaddresses_by_asset_participant(
            asset,
            address,
        )

        count[pex(address)] = len(addresses)

    log.debug('total count of channels:', count=count)


def create_channels(chain_service, assets_list, apps, channels_per_node,
                    deposit=DEFAULT_DEPOSIT):
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
        addresses = chain_service.nettingaddresses_by_asset_participant(
            asset,
            app.raiden.address,
        )

        return len(addresses)

    # Create `channels_per_node` channels for each asset in each app
    for asset_address, curr_app in product(assets_list, sorted(apps, key=sort_by_address)):
        curr_address = curr_app.raiden.address

        contracts_addreses = chain_service.nettingaddresses_by_asset_participant(
            asset_address,
            curr_address,
        )

        # get a list of apps that the current node doesn't have a channel with
        other_apps = list(apps)
        other_apps.remove(curr_app)

        for address in contracts_addreses:
            peer_address = chain_service.partner(asset_address, address, curr_address)

            for app in other_apps:
                if app.raiden.address == peer_address:
                    other_apps.remove(app)

        print_channel_count(chain_service, asset_address, apps)

        # create and initialize the missing channels
        while len(contracts_addreses) < channels_per_node:
            app = sorted(other_apps, key=lambda app: sort_by_channelcount(asset_address, app))[0]  # pylint: disable=cell-var-from-loop
            other_apps.remove(app)

            netcontract_address = chain_service.new_netting_contract(
                asset_address,
                app.raiden.address,
                curr_app.raiden.address,
            )
            contracts_addreses.append(netcontract_address)

            for address in [curr_app.raiden.address, app.raiden.address]:
                chain_service.deposit(
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

    log.info(
        'creating a new test network',
        num_nodes=num_nodes,
        num_assets=num_assets,
        channels_per_node=channels_per_node,
    )

    random.seed(1337)

    if channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    client_hosts = ['127.0.0.10', '127.0.0.11']

    # if num_nodes it is not even
    half_of_nodes = int(ceil(num_nodes / 2))

    # globals
    discovery = PredictiveDiscovery((
        (host, half_of_nodes)
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

    create_channels(blockchain_service, asset_list, apps, channels_per_node)

    for app in apps:
        app.raiden.setup_assets(asset_list)

    return apps
