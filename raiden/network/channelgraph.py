# -*- coding: utf-8 -*-
import logging
from collections import namedtuple
from heapq import heappush, heappop

import networkx
from ethereum import slogging

from raiden.utils import isaddress, pex
from raiden.transfer.state import (
    RouteState,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
)
from raiden.channel.netting_channel import (
    Channel,
)
from raiden.network.protocol import (
    NODE_NETWORK_REACHABLE,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

ChannelDetails = namedtuple(
    'ChannelDetails',
    (
        'channel_address',
        'our_state',
        'partner_state',
        'external_state',
        'reveal_timeout',
        'settle_timeout',
    )
)


def make_graph(edge_list):
    """ Return a graph that represents the connections among the netting
    contracts.

    Args:
        edge_list (List[(address1, address2)]): All the channels that compose
            the graph.

    Returns:
        Graph A networkx.Graph instance were the graph nodes are nodes in the
            network and the edges are nodes that have a channel between them.
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


def channel_to_routestate(channel, node_address):
    state = channel.state
    channel_address = channel.external_state.netting_channel.address
    distributable = channel.distributable
    settle_timeout = channel.settle_timeout
    reveal_timeout = channel.reveal_timeout

    if state == CHANNEL_STATE_CLOSED:
        closed_block = channel.external_state.closed_block
    else:
        closed_block = None

    state = RouteState(
        state=state,
        node_address=node_address,
        channel_address=channel_address,
        available_balance=distributable,
        settle_timeout=settle_timeout,
        reveal_timeout=reveal_timeout,
        closed_block=closed_block,
    )

    return state


def ordered_neighbors(nx_graph, our_address, target_address):
    paths = list()

    try:
        all_neighbors = networkx.all_neighbors(nx_graph, our_address)
    except networkx.NetworkXError:
        # If `our_address` is not in the graph, no channels opened with the
        # address
        return []

    for neighbor in all_neighbors:
        try:
            length = networkx.shortest_path_length(
                nx_graph,
                neighbor,
                target_address,
            )
            heappush(paths, (length, neighbor))
        except (networkx.NetworkXNoPath, networkx.NodeNotFound):
            pass

    return paths


def get_best_routes(
        channel_graph,
        nodeaddresses_statuses,
        our_address,
        target_address,
        amount,
        previous_address=None):

    """ Yield a two-tuple (path, channel) that can be used to mediate the
    transfer. The result is ordered from the best to worst path.
    """

    # XXX: consider using multiple channels for a single transfer. Useful
    # for cases were the `amount` is larger than what is available
    # individually in any of the channels.
    #
    # One possible approach is to _not_ filter these channels based on the
    # distributable amount, but to sort them based on available balance and
    # let the task use as many as required to finish the transfer.

    online_nodes = list()

    neighbors_heap = ordered_neighbors(
        channel_graph.graph,
        our_address,
        target_address,
    )

    if not neighbors_heap and log.isEnabledFor(logging.WARNING):
        log.warn(
            'no routes available from %s to %s',
            pex(our_address),
            pex(target_address),
        )

    while neighbors_heap:
        _, partner_address = heappop(neighbors_heap)
        channel = channel_graph.partneraddress_to_channel[partner_address]

        # don't send the message backwards
        if partner_address == previous_address:
            continue

        if channel.state != CHANNEL_STATE_OPENED:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'channel %s - %s is not opened, ignoring',
                    pex(our_address),
                    pex(partner_address),
                )
            continue

        if amount > channel.distributable:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'channel %s - %s doesnt have enough funds [%s], ignoring',
                    pex(our_address),
                    pex(partner_address),
                    amount,
                )
            continue

        network_state = nodeaddresses_statuses[partner_address]
        route_state = channel_to_routestate(channel, partner_address)

        if network_state != NODE_NETWORK_REACHABLE:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'partner for channel %s - %s is not %s, ignoring',
                    pex(our_address),
                    pex(partner_address),
                    NODE_NETWORK_REACHABLE,
                )
            continue

        online_nodes.append(route_state)

    return online_nodes


class ChannelGraph:
    """ Has Graph based on the channels and can find path between participants. """

    def __init__(
            self,
            our_address,
            channelmanager_address,
            token_address,
            edge_list,
            channels_details):

        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        graph = make_graph(edge_list)
        self.address_to_channel = dict()
        self.graph = graph
        self.our_address = our_address
        self.partneraddress_to_channel = dict()
        self.token_address = token_address
        self.channelmanager_address = channelmanager_address

        for details in channels_details:
            try:
                self.add_channel(details)
            except ValueError as e:
                log.warn(
                    'Error at registering opened channel contract. Perhaps contract is invalid?',
                    error=str(e),
                    channel_address=pex(details.channel_address)
                )

    def __eq__(self, other):
        if isinstance(other, ChannelGraph):
            return (
                self.address_to_channel == other.address_to_channel and
                # networkx.classes.graph.Graph has no __eq__
                self.graph.__dict__ == other.graph.__dict__ and
                self.our_address == other.our_address and
                self.partneraddress_to_channel == other.partneraddress_to_channel and
                self.token_address == other.token_address and
                self.channelmanager_address == other.channelmanager_address
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def add_channel(self, details):
        """ Instantiate a channel this node participates and add to the graph.

        If the channel is already registered do nothing.
        """
        channel_address = details.channel_address

        if details.our_state.address != self.our_address:
            raise ValueError(
                "Address mismatch, our_address doesn't match the channel details"
            )

        if channel_address not in self.address_to_channel:
            partner_state = details.partner_state

            channel = Channel(
                details.our_state,
                partner_state,
                details.external_state,
                self.token_address,
                details.reveal_timeout,
                details.settle_timeout,
            )
            self.add_path(details.our_state.address, partner_state.address)

            self.partneraddress_to_channel[partner_state.address] = channel
            self.address_to_channel[channel_address] = channel

    def get_channel_by_contract_address(self, netting_channel_address):
        """ Return the channel with `netting_channel_address`.

        Raises:
            KeyError: If there is no channel with netting_channel_address.
        """
        return self.address_to_channel[netting_channel_address]

    def get_shortest_paths(self, source, target):
        """Compute all shortest paths in the graph.

        Returns:
            generator of lists: A generator of all paths between source and
            target.
        """
        if not isaddress(source) or not isaddress(target):
            raise ValueError('both source and target must be valid addresses')

        return networkx.all_shortest_paths(self.graph, source, target)

    def get_paths_of_length(self, source, num_hops=1):
        """ Searchs for all nodes that are `num_hops` away.

        Returns:
            list of paths: A list of all shortest paths that have length
            `num_hops + 1`
        """
        # return a dictionary keyed by targets
        # with a list of nodes in a shortest path
        # from the source to one of the targets.
        all_paths = networkx.shortest_path(self.graph, source)

        return [
            path
            for path in all_paths.values()
            if len(path) == num_hops + 1
        ]

    def has_path(self, source_address, target_address):
        """ True if there is a connecting path regardless of the number of hops. """
        try:
            return networkx.has_path(self.graph, source_address, target_address)
        except (networkx.NodeNotFound, networkx.NetworkXNoPath):
            return False

    def has_channel(self, source_address, target_address):
        """ True if there is a channel connecting both addresses. """
        return self.graph.has_edge(source_address, target_address)

    def add_path(self, from_address, to_address):
        """ Add a new edge into the network. """
        self.graph.add_edge(from_address, to_address)

    def remove_path(self, from_address, to_address):
        """ Remove an edge from the network. """
        self.graph.remove_edge(from_address, to_address)

    def channel_can_transfer(self, partner_address):
        """ True if the channel with `partner_address` is open and has spendable funds. """
        # TODO: check if the partner's network is alive
        return self.partneraddress_to_channel[partner_address].can_transfer

    def get_neighbours(self):
        """ Get all neihbours adjacent to self.our_address. """
        try:
            return networkx.all_neighbors(self.graph, self.our_address)
        except networkx.NetworkXError:
            return []
