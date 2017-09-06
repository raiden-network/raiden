# -*- coding: utf-8 -*-
""" Utilities to set-up a Raiden network. """
from __future__ import print_function, division


from ethereum import slogging

from raiden.app import App
from raiden.network.transport import DummyPolicy
from raiden.utils import privatekey_to_address
from raiden.tests.utils import OwnedNettingChannel

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

CHAIN = object()  # Flag used by create a network does make a loop with the channels


def check_channel(app1, app2, netting_channel_address, deposit_amount):
    # proxying the NettingChannel with OwnedNettingChannel allows us to use both, tester and mock.
    netcontract1 = OwnedNettingChannel(
        app1.raiden.address,
        app1.raiden.chain.netting_channel(netting_channel_address)
    )

    netcontract2 = OwnedNettingChannel(
        app2.raiden.address,
        app2.raiden.chain.netting_channel(netting_channel_address)
    )

    if deposit_amount > 0:
        assert netcontract1.can_transfer()
        assert netcontract2.can_transfer()

    app1_details = netcontract1.detail()
    app2_details = netcontract2.detail()

    assert app1_details['our_address'] == app2_details['partner_address']
    assert app1_details['partner_address'] == app2_details['our_address']

    assert app1_details['our_balance'] == app2_details['partner_balance']
    assert app1_details['partner_balance'] == app2_details['our_balance']


def setup_channels(token_address, app_pairs, deposit, settle_timeout):
    for first, second in app_pairs:
        assert token_address

        manager = first.raiden.chain.manager_by_token(token_address)

        netcontract_address = manager.new_netting_channel(
            first.raiden.address,
            second.raiden.address,
            settle_timeout,
        )

        assert netcontract_address

        # use each app's own chain because of the private key / local signing
        for app in [first, second]:
            token = app.raiden.chain.token(token_address)
            netting_channel = app.raiden.chain.netting_channel(netcontract_address)
            previous_balance = token.balance_of(app.raiden.address)

            assert previous_balance >= deposit

            token.approve(netcontract_address, deposit)
            netting_channel.deposit(deposit)

            new_balance = token.balance_of(app.raiden.address)

            assert previous_balance - deposit == new_balance

            # netting contract does allow settle time lower than 30
            contract_settle_timeout = netting_channel.settle_timeout()
            assert contract_settle_timeout == max(6, settle_timeout)

        check_channel(
            first,
            second,
            netcontract_address,
            deposit,
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

    # Create `channels_per_node` channels for each token in each app
    # for token_address, curr_app in product(tokens_list, sorted(apps, key=sort_by_address)):

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


def create_network_channels(
        raiden_apps,
        token_addresses,
        channels_per_node,
        deposit,
        settle_timeout):

    num_nodes = len(raiden_apps)

    if channels_per_node is not CHAIN and channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    for token in token_addresses:
        if channels_per_node == CHAIN:
            app_channels = list(zip(raiden_apps[:-1], raiden_apps[1:]))
        else:
            app_channels = list(network_with_minimum_channels(raiden_apps, channels_per_node))

        setup_channels(
            token,
            app_channels,
            deposit,
            settle_timeout,
        )


def create_sequential_channels(
        raiden_apps,
        token_addresses,
        channels_per_node,
        deposit,
        settle_timeout):
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

    setup_channels(
        token_addresses,
        app_channels,
        deposit,
        settle_timeout,
    )


def create_apps(
        blockchain_services,
        endpoint_discovery_services,
        raiden_udp_ports,
        transport_class,
        reveal_timeout,
        settle_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout):

    """ Create the apps.

    Note:
        The generated network will use two subnets, 127.0.0.10 and 127.0.0.11,
        for this test to work in a mac both virtual interfaces must be created
        prior to the test execution::

            MacOSX (tested on 10.11.5):
                         interface       ip address netmask
                ifconfig lo0       alias 127.0.0.10 255.255.255.0
                ifconfig lo0       alias 127.0.0.11 255.255.255.0

            Alternative syntax:
                ifconfig lo:0 127.0.0.10
                ifconfig lo:1 127.0.0.11
    """
    # pylint: disable=too-many-locals
    half_of_nodes = len(blockchain_services) // 2

    services = zip(blockchain_services, endpoint_discovery_services)

    apps = []
    for idx, (blockchain, discovery) in enumerate(services):
        port = raiden_udp_ports[idx]
        private_key = blockchain.private_key
        nodeid = privatekey_to_address(private_key)

        # split the nodes into two different networks
        if idx > half_of_nodes:
            # TODO: check if the loopback interfaces exists
            host = '127.0.0.11'
        else:
            host = '127.0.0.10'

        discovery.register(nodeid, host, port)

        config = {
            'host': host,
            'port': port,
            'external_ip': host,
            'external_port': port,
            'privatekey_hex': private_key.encode('hex'),
            'reveal_timeout': reveal_timeout,
            'settle_timeout': settle_timeout,
            'database_path': database_paths[idx],
            'protocol': {
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
        copy = App.DEFAULT_CONFIG.copy()
        copy.update(config)

        app = App(
            copy,
            blockchain,
            discovery,
            transport_class,
        )
        app.raiden.protocol.transport.throttle_policy = DummyPolicy()
        apps.append(app)

    return apps
