from typing import List, Tuple
from heapq import heappush, heappop

import networkx
import structlog
from eth_utils import is_binary_address

from raiden.transfer import channel, views
from raiden.transfer.state import (
    ChainState,
    CHANNEL_STATE_OPENED,
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
)
from raiden.utils import pex, typing
from raiden.transfer.state import RouteState

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def make_graph(
        edge_list: List[Tuple[typing.Address, typing.Address]],
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

        if not is_binary_address(origin) or not is_binary_address(destination):
            raise ValueError('All values in edge_list must be valid addresses')

    graph = networkx.Graph()  # undirected graph, for bidirectional channels

    for first, second in edge_list:
        graph.add_edge(first, second)

    return graph


def get_ordered_partners(
        network_graph: networkx.Graph,
        from_address: typing.Address,
        to_address: typing.Address,
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
        chain_state: ChainState,
        token_network_id: typing.Address,
        from_address: typing.Address,
        to_address: typing.Address,
        amount: int,
        previous_address: typing.Address,
) -> List[RouteState]:
    """ Returns a list of channels that can be used to make a transfer.

    This will filter out channels that are not open and don't have enough
    capacity.
    """
    # TODO: Route ranking.
    # Rate each route to optimize the fee price/quality of each route and add a
    # rate from in the range [0.0,1.0].

    available_routes = list()

    token_network = views.get_token_network_by_identifier(
        chain_state,
        token_network_id,
    )

    network_statuses = views.get_networkstatuses(chain_state)

    neighbors_heap = get_ordered_partners(
        token_network.network_graph.network,
        from_address,
        to_address,
    )

    if not neighbors_heap:
        log.warning(
            'No routes available from %s to %s' % (pex(from_address), pex(to_address)),
        )

    while neighbors_heap:
        _, partner_address = heappop(neighbors_heap)

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state,
            token_network_id,
            partner_address,
        )

        # don't send the message backwards
        if partner_address == previous_address:
            continue

        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            log.info(
                'channel %s - %s is not opened, ignoring' %
                (pex(from_address), pex(partner_address)),
            )
            continue

        distributable = channel.get_distributable(
            channel_state.our_state,
            channel_state.partner_state,
        )

        if amount > distributable:
            log.info(
                'channel %s - %s doesnt have enough funds [%s], ignoring' %
                (pex(from_address), pex(partner_address), amount),
            )
            continue

        network_state = network_statuses.get(partner_address, NODE_NETWORK_UNKNOWN)
        if network_state != NODE_NETWORK_REACHABLE:
            log.info(
                'partner for channel %s - %s is not %s, ignoring' %
                (pex(from_address), pex(partner_address), NODE_NETWORK_REACHABLE),
            )
            continue

        route_state = RouteState(partner_address, channel_state.identifier)
        available_routes.append(route_state)

    return available_routes
