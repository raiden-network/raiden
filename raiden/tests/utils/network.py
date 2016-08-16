# -*- coding: utf8 -*-
""" Utilities to set-up a Raiden network. """
from __future__ import print_function, division

import copy
from ethereum.keys import privtoaddr
from ethereum import slogging

from raiden.app import App, INITIAL_PORT
from raiden.network.discovery import Discovery

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

CHAIN = object()  # Flag used by create a network does make a loop with the channels


def check_channel(app1, app2, netting_channel_address):
    netcontract1 = app1.raiden.chain.netting_channel(netting_channel_address)
    netcontract2 = app2.raiden.chain.netting_channel(netting_channel_address)

    assert netcontract1.isopen()
    assert netcontract2.isopen()

    assert netcontract1.detail(app1.raiden.address) == netcontract2.detail(app1.raiden.address)
    assert netcontract2.detail(app2.raiden.address) == netcontract1.detail(app2.raiden.address)

    app1_details = netcontract1.detail(app1.raiden.address)
    app2_details = netcontract2.detail(app2.raiden.address)

    assert app1_details['our_address'] == app2_details['partner_address']
    assert app1_details['partner_address'] == app2_details['our_address']

    assert app1_details['our_balance'] == app2_details['partner_balance']
    assert app1_details['partner_balance'] == app2_details['our_balance']


def create_app(privatekey_bin, chain, discovery, transport_class, port,
               host='127.0.0.1'):
    ''' Instantiates an Raiden app with the given configuration. '''
    config = copy.deepcopy(App.default_config)

    config['port'] = port
    config['host'] = host
    config['privatekey_hex'] = privatekey_bin.encode('hex')

    return App(
        config,
        chain,
        discovery,
        transport_class,
    )


def setup_channels(asset_address, app_pairs, deposit, settle_timeout):
    for first, second in app_pairs:
        assert len(asset_address)
        manager = first.raiden.chain.manager_by_asset(asset_address)

        netcontract_address = manager.new_netting_channel(
            first.raiden.address,
            second.raiden.address,
            settle_timeout,
        )
        assert len(netcontract_address)

        # use each app's own chain because of the private key / local signing
        for app in [first, second]:
            asset = app.raiden.chain.asset(asset_address)
            netting_channel = app.raiden.chain.netting_channel(netcontract_address)
            previous_balance = asset.balance_of(app.raiden.address)

            assert previous_balance >= deposit

            asset.approve(netcontract_address, deposit)
            netting_channel.deposit(app.raiden.address, deposit)

            new_balance = asset.balance_of(app.raiden.address)

            assert previous_balance - deposit == new_balance

            # netting contract does allow settle time lower than 30
            contract_settle_timeout = netting_channel.settle_timeout()
            assert contract_settle_timeout == max(6, settle_timeout)

        check_channel(
            first,
            second,
            netcontract_address,
        )

        first_netting_channel = first.raiden.chain.netting_channel(netcontract_address)
        second_netting_channel = second.raiden.chain.netting_channel(netcontract_address)

        details1 = first_netting_channel.detail(first.raiden.address)
        details2 = second_netting_channel.detail(second.raiden.address)

        assert details1['our_balance'] == deposit
        assert details1['partner_balance'] == deposit
        assert details2['our_balance'] == deposit
        assert details2['partner_balance'] == deposit


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

    # Create `channels_per_node` channels for each asset in each app
    # for asset_address, curr_app in product(assets_list, sorted(apps, key=sort_by_address)):

    # sorting the apps and use the next n apps to make a channel to avoid edge
    # cases
    for curr_app in sorted(apps, key=lambda app: app.raiden.address):
        available_apps = unconnected_apps[curr_app.raiden.address]

        while channel_count[curr_app.raiden.address] < channels_per_node:
            least_connect = sorted(
                available_apps,
                key=lambda app: channel_count[app.raiden.address]
            )[0]

            channel_count[curr_app.raiden.address] += 1
            available_apps.remove(least_connect)

            channel_count[least_connect.raiden.address] += 1
            unconnected_apps[least_connect.raiden.address].remove(curr_app)

            yield curr_app, least_connect


def create_network(blockchain_services, assets_addresses, channels_per_node,
                   deposit, settle_timeout, transport_class, verbosity):
    """ Initialize a raiden test network.

    Note:
        The generated network will use two subnets, 127.0.0.10 and 127.0.0.11,
        for this test to work in a mac both virtual interfaces must be created
        prior to the test execution::

            ifconfig lo:0 127.0.0.10
            ifconfig lo:1 127.0.0.11
    """
    # pylint: disable=too-many-locals

    num_nodes = len(blockchain_services)

    if channels_per_node is not CHAIN and channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    half_of_nodes = len(blockchain_services) // 2
    discovery = Discovery()

    apps = []
    for idx, blockchain in enumerate(blockchain_services):
        private_key = blockchain.private_key

        # TODO: check if the loopback interfaces exists
        # split the nodes into two different networks
        if idx > half_of_nodes:
            host = '127.0.0.11'
        else:
            host = '127.0.0.10'

        nodeid = privtoaddr(private_key)
        port = INITIAL_PORT + idx

        discovery.register(nodeid, host, port)

        if verbosity > 7:
            blockchain.set_verbose()

        app = create_app(
            private_key,
            blockchain,
            discovery,
            transport_class,
            port=port,
            host=host,
        )
        apps.append(app)

    for asset in assets_addresses:
        if channels_per_node == CHAIN:
            app_channels = list(zip(apps[:-1], apps[1:]))
        else:
            app_channels = list(network_with_minimum_channels(apps, channels_per_node))

        setup_channels(
            asset,
            app_channels,
            deposit,
            settle_timeout,
        )

    for app in apps:
        app.raiden.register_registry(app.raiden.chain.default_registry)

    return apps


def create_sequential_network(blockchain_services, asset_address,
                              channels_per_node, deposit, settle_timeout,
                              transport_class, verbosity):
    """ Create a fully connected network with `num_nodes`, the nodes are
    connect sequentially.

    Returns:
        A list of apps of size `num_nodes`, with the property that every
        sequential pair in the list has an open channel with `deposit` for each
        participant.
    """
    # pylint: disable=too-many-locals

    host = '127.0.0.1'
    num_nodes = len(blockchain_services)

    if num_nodes < 2:
        raise ValueError('cannot create a network with less than two nodes')

    if channels_per_node not in (0, 1, 2, CHAIN):
        raise ValueError('can only create networks with 0, 1, 2 or CHAIN channels')

    discovery = Discovery()

    apps = []
    for idx, blockchain in enumerate(blockchain_services):
        port = INITIAL_PORT + idx
        private_key = blockchain.private_key
        nodeid = privtoaddr(private_key)

        discovery.register(nodeid, host, port)

        if verbosity > 7:
            blockchain.set_verbose()

        app = create_app(
            private_key,
            blockchain,
            discovery,
            transport_class,
            port=port,
            host=host,
        )
        apps.append(app)

    if channels_per_node == 0:
        app_channels = list()

    if channels_per_node == 1:
        every_two = iter(apps)
        app_channels = list(zip(every_two, every_two))

    if channels_per_node == 2:
        app_channels = list(zip(apps, apps[1:] + [apps[0]]))

    if channels_per_node == CHAIN:
        app_channels = list(zip(apps[:-1], apps[1:]))

    setup_channels(
        asset_address,
        app_channels,
        deposit,
        settle_timeout,
    )

    for app in apps:
        app.raiden.register_registry(app.raiden.chain.default_registry)

    return apps
