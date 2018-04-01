# -*- coding: utf-8 -*-
import logging
from typing import List, Tuple
from heapq import heappush, heappop

import networkx
from ethereum import slogging

from raiden.transfer import channel, views
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
)
from raiden.utils import isaddress, pex, typing
from raiden.transfer.state import RouteState

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def make_graph(
    edge_list: List[Tuple[typing.address, typing.address]]
) -> networkx.Graph:
    """ Returns a graph that represents the connections among the netting
    contracts.
    Args:
        edge_list: All the channels that compose the graph.
    Returns:
        A graph where the nodes are nodes in the network and the edges are
        nodes that have a channel between them.
    """

    for edge in edge_list:
        if len(edge) != 2:
            raise ValueError('All values in edge_list must be of length two (origin, destination)')

        origin, destination = edge

        if not isaddress(origin) or not isaddress(destination):
            raise ValueError('All values in edge_list must be valid addresses')

    graph = networkx.Graph()  # undirected graph, for bidirectional channels

    for first, second in edge_list:
        graph.add_edge(first, second)

    return graph


def get_ordered_partners(
    network_graph: networkx.Graph,
    from_address: typing.address,
    to_address: typing.address
) -> List:
    paths = list()

    try:
        all_neighbors = networkx.all_neighbors(network_graph, from_address)
    except networkx.NetworkXError:
        # If `our_address` is not in the graph, no channels opened with the
        # address
        return []

    for neighbor in all_neighbors:
        try:
            length = networkx.shortest_path_length(
                network_graph,
                neighbor,
                to_address,
            )
            heappush(paths, (length, neighbor))
        except (networkx.NetworkXNoPath, networkx.NodeNotFound):
            pass

    return paths


def get_best_routes(
    node_state: 'NodeState',
    payment_network_id: typing.address,
    token_address: typing.address,
    from_address: typing.address,
    to_address: typing.address,
    amount: int,
    previous_address: typing.address,
) -> List[RouteState]:
    """ Returns a list of channels that can be used to make a transfer.

    This will filter out channels that are not open and don't have enough
    capacity.
    """
    # TODO: Route ranking.
    # Rate each route to optimize the fee price/quality of each route and add a
    # rate from in the range [0.0,1.0].

    available_routes = list()

    token_network = views.get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    network_statuses = views.get_networkstatuses(node_state)

    neighbors_heap = get_ordered_partners(
        token_network.network_graph.network,
        from_address,
        to_address,
    )

    if not neighbors_heap and log.isEnabledFor(logging.WARNING):
        log.warn(
            'No routes available from %s to %s',
            pex(from_address),
            pex(to_address),
        )

    while neighbors_heap:
        _, partner_address = heappop(neighbors_heap)

        channel_state = views.get_channelstate_for(
            node_state,
            payment_network_id,
            token_address,
            partner_address,
        )

        # don't send the message backwards
        if partner_address == previous_address:
            continue

        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'channel %s - %s is not opened, ignoring',
                    pex(from_address),
                    pex(partner_address),
                )
            continue

        distributable = channel.get_distributable(
            channel_state.our_state,
            channel_state.partner_state,
        )

        if amount > distributable:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'channel %s - %s doesnt have enough funds [%s], ignoring',
                    pex(from_address),
                    pex(partner_address),
                    amount,
                )
            continue

        network_state = network_statuses.get(partner_address, NODE_NETWORK_UNKNOWN)
        if network_state != NODE_NETWORK_REACHABLE:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'partner for channel %s - %s is not %s, ignoring',
                    pex(from_address),
                    pex(partner_address),
                    NODE_NETWORK_REACHABLE,
                )
            continue

        route_state = RouteState(partner_address, channel_state.identifier)
        available_routes.append(route_state)

    return available_routes
