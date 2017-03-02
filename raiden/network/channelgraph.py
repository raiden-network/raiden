# -*- coding: utf-8 -*-
import logging
from collections import namedtuple

import networkx
from ethereum import slogging

from raiden.utils import isaddress, pex
from raiden.channel import Channel

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
ChannelDetail = namedtuple(
    'ChannelDetail',
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


class ChannelGraph(object):
    """ Has Graph based on the channels and can find path between participants. """

    def __init__(self, our_address_bin, token_address_bin, edge_list, channels_detail):
        if not isaddress(token_address_bin):
            raise ValueError('token_address_bin must be a valid address')

        graph = make_graph(edge_list)
        self.address_channel = dict()
        self.graph = graph
        self.our_address_bin = our_address_bin
        self.partneraddress_channel = dict()
        self.token_address = token_address_bin

        for detail in channels_detail:
            self.add_channel(detail)

    def add_channel(self, detail):
        channel_address = detail.channel_address
        partner_state = detail.partner_state

        channel = Channel(
            detail.our_state,
            partner_state,
            detail.external_state,
            self.token_address,
            detail.reveal_timeout,
            detail.settle_timeout,
        )

        self.partneraddress_channel[partner_state.address] = channel
        self.address_channel[channel_address] = channel

    def get_channel_by_contract_address(self, netting_channel_address_bin):
        """ Return the channel with `netting_channel_address_bin`.

        Raises:
            KeyError: If there is no channel with netting_channel_address_bin.
        """
        return self.address_channel[netting_channel_address_bin]

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

    def get_best_routes(self, our_address_bin, target_address_bin, amount, lock_timeout=None):
        """ Yield a two-tuple (path, channel) that can be used to mediate the
        transfer. The result is ordered from the best to worst path.
        """
        available_paths = self.get_shortest_paths(
            our_address_bin,
            target_address_bin,
        )

        # XXX: consider using multiple channels for a single transfer. Useful
        # for cases were the `amount` is larger than what is available
        # individually in any of the channels.
        #
        # One possible approach is to _not_ filter these channels based on the
        # distributable amount, but to sort them based on available balance and
        # let the task use as many as required to finish the transfer.

        for path in available_paths:
            partner = path[1]
            channel = self.partneraddress_channel[partner]

            if not channel.isopen:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'channel %s - %s is close, ignoring',
                        pex(path[0]),
                        pex(path[1]),
                    )

                continue

            # we can't intermediate the transfer if we don't have enough funds
            if amount > channel.distributable:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'channel %s - %s doesnt have enough funds [%s], ignoring',
                        pex(path[0]),
                        pex(path[1]),
                        amount,
                    )
                continue

            if lock_timeout:
                # Our partner wont accept a lock timeout that:
                # - is larger than the settle timeout, otherwise the lock's
                # secret could be release /after/ the channel is settled.
                # - is smaller than the reveal timeout, because that is the
                # minimum number of blocks required by the partner to learn the
                # secret.
                valid_timeout = channel.reveal_timeout <= lock_timeout < channel.settle_timeout

                if not valid_timeout and log.isEnabledFor(logging.INFO):
                    log.info(
                        'lock_expiration is too large, channel/path cannot be used',
                        lock_timeout=lock_timeout,
                        reveal_timeout=channel.reveal_timeout,
                        settle_timeout=channel.settle_timeout,
                        nodeid=pex(path[0]),
                        partner=pex(path[1]),
                    )

                # do not try the route since we know the transfer will be rejected.
                if not valid_timeout:
                    continue

            yield (path, channel)

    def has_path(self, source_address_bin, target_address_bin):
        """ True if there is a connecting path regarless of number of hops. """
        return networkx.has_path(self.graph, source_address_bin, target_address_bin)

    def has_channel(self, source_address_bin, target_address_bin):
        """ True if there is a channel connecting both addresses. """
        return self.graph.has_edge(source_address_bin, target_address_bin)

    def add_path(self, from_address_bin, to_address_bin):
        """ Add a new edge into the network. """
        self.graph.add_edge(from_address_bin, to_address_bin)

    def remove_path(self, from_address_bin, to_address_bin):
        """ Remove an edge from the network. """
        self.graph.remove_edge(from_address_bin, to_address_bin)

    def channel_isactive(self, partner_address_bin):
        """ True if the channel with `partner_address` is open. """
        # TODO: check if the partner's network is alive
        return self.partneraddress_channel[partner_address_bin].isopen
