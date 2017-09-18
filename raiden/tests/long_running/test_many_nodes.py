# -*- coding: utf-8 -*-
import pytest
import gevent
import random
import networkx as nx
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.network import setup_channels
from raiden.utils import pex

from ethereum import slogging

log = slogging.getLogger(__name__)

#
# This test will create a huge network of raiden nodes and will attempt
#   to create many direct and mediated transfers among the nodes.
#
# It is assumed that the network graph is connected and that there are
#   no circles in the graph (so the graph is a tree). The NetworkX library
#   generator is used to create the graph in order to guarantee this properties
#
#
#


@pytest.mark.parametrize('number_of_nodes', [50])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('deposit', [1000])
@pytest.mark.parametrize('settle_timeout', [1000])
@pytest.mark.parametrize('reveal_timeout', [50])
def test_many_nodes(
    raiden_network,
    token_addresses,
    settle_timeout,
    reveal_timeout,
    deposit
):
    # create initial topology (a graph without loops)
    network_graph = nx.barabasi_albert_graph(
        len(raiden_network),    # n = number of nodes
        3)                      # m = number of edges
    app_channels = [
        (raiden_network[edge[0]], raiden_network[edge[1]])
        for edge in network_graph.edges()]

    #  at the moment, route length for a mediated transaction
    # is limited be these two values
    max_hops = settle_timeout // reveal_timeout / 2

    setup_channels(
        token_addresses[0],
        app_channels,
        100,
        settle_timeout,
    )
    log.debug("sleeping ....")
    gevent.sleep(5)

    # make list of all channels and sum the initial balance
    initial_balance = 0
    end_balance = 0
    for app in raiden_network:
        channelgraph = app.raiden.token_to_channelgraph.values()[0]
        initial_balance += sum(channel.balance
                               for channel in
                               channelgraph.address_to_channel.values())

    assert initial_balance > 0
    gevent.sleep(5)
    # do one transfer per app to a randomly selected participant
    token = token_addresses[0]
    async_list = []

    for app in raiden_network:
        targets = nx.single_source_dijkstra_path_length(network_graph, raiden_network.index(app))
        targets = [node for node, length in targets.iteritems() if length < (max_hops - 1)]
        while True:
            target = raiden_network[random.choice(targets)]
            if target != app:
                break

        shortest_path = nx.all_shortest_paths(
            network_graph,
            raiden_network.index(app),
            raiden_network.index(target))
        for path in shortest_path:
            path_str = ""
            for node_id in path:
                path_str += "%s[%d] > " % (pex(raiden_network[node_id].raiden.address), node_id)
            log.info("shortest path : %s" % (path_str))
            assert len(path) < max_hops
        log.info("starting transfer %s > %s @%d" % (
            pex(app.raiden.address), pex(target.raiden.address),
            app.raiden.chain.block_number()))
        transfer_event = app.raiden.transfer_async(
            token,
            1,
            target.raiden.address
        )
        assert transfer_event
        async_list.append(transfer_event)

    for async_result in async_list:
        assert async_result.wait()

    app = raiden_network[0]
    settle_expiration = app.raiden.chain.block_number() + settle_timeout + 5
    wait_until_block(app.raiden.chain, settle_expiration)
    gevent.sleep(5)

    # check if balances are right
    for app in raiden_network:
        channelgraph = app.raiden.token_to_channelgraph.values()[0]
        end_balance += sum(channel.balance for channel in channelgraph.address_to_channel.values())
    assert initial_balance == end_balance
