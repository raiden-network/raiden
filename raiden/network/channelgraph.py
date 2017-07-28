# -*- coding: utf-8 -*-
import logging
from collections import namedtuple

import networkx
from ethereum import slogging

from functools import total_ordering

from raiden.utils import isaddress, pex
from raiden.transfer.state import (
    RouteState,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
)
from raiden.network.protocol import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNREACHABLE,
    NODE_NETWORK_UNKNOWN
)
from raiden.channel.netting_channel import (
    Channel,
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


#  To sort multiple-keyed list we use redefined __lt__ method,
# which is then used by sorted()
@total_ordering
class RouteOrderedItem:
    def __init__(self, distance_to_target, node_state, route_state):
        assert isinstance(route_state, RouteState)
        self.distance_to_target = distance_to_target  # key1
        self.node_state = node_state                  # key2
        self.route_state = route_state                # value

    def __lt__(self, other):
        if not isinstance(other, RouteOrderedItem):
            return False
        state_order = [
            NODE_NETWORK_REACHABLE,
            NODE_NETWORK_UNKNOWN,
            NODE_NETWORK_UNREACHABLE]
        assert self.node_state in state_order
        assert other.node_state in state_order
        if self.distance_to_target == other.distance_to_target:
            return (state_order.index(self.node_state) <
                    state_order.index(other.node_state))
        return self.distance_to_target < other.distance_to_target

    def __eq__(self, other):
        if not isinstance(other, RouteOrderedItem):
            return False
        return ((self.distance_to_target == other.distance_to_target) and
                (self.node_state == other.node_state))

    def __ne__(self, other):
        return not self.__eq__(other)


def ordered_neighbors(nx_graph, our_address, target_address):
    """Return neighbors that can reach the target"""
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
            paths.append((length, neighbor))
        except networkx.NetworkXNoPath:
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

    routable_neighbors = list()
    neighbors = ordered_neighbors(channel_graph.graph, our_address, target_address)

    for hops, partner_address in neighbors:
        # don't send the message backwards
        channel = channel_graph.partneraddress_to_channel[partner_address]
        if partner_address == previous_address:
            continue

        if not channel.can_transfer:
            if log.isEnabledFor(logging.INFO):
                log.info(
                    'channel %s - %s is closed or has zero funding, ignoring',
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

        if channel.state != CHANNEL_STATE_OPENED:
            continue

        route_state = channel_to_routestate(channel, partner_address)
        routable_neighbors.append(
            RouteOrderedItem(
                hops,
                nodeaddresses_statuses[partner_address],
                route_state))

    # order of items is defined by RouteOrderedItem.__lt__()
    #  We return list sorted by shortest_path, node_status, so preferentially
    # the shortest path is tried, and only if two paths of a same size exist,
    # we use the path that is in an 'reachable' state
    return [item.route_state for item in sorted(routable_neighbors)
            if item.route_state is not NODE_NETWORK_UNREACHABLE]


class ChannelGraph(object):
    """ Has Graph based on the channels and can find path between participants. """

    def __init__(
            self,
            our_address,
            channelmanager_address,
            token_address,
            edge_list,
            channels_details,
            block_number):

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
            self.add_channel(details)

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
        channel_address = details.channel_address
        partner_state = details.partner_state

        channel = Channel(
            details.our_state,
            partner_state,
            details.external_state,
            self.token_address,
            details.reveal_timeout,
            details.settle_timeout,
        )

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
        except networkx.NetworkXError:
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
