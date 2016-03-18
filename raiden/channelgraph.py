# -*- coding: utf8 -*-
import networkx as nx

from raiden.contracts import ChannelManagerContract, NettingChannelContract
from raiden.utils import isaddress


class ChannelGraph(object):
    """ Has Graph based on the channels and can find path between participants. """

    def __init__(self, channelmanager):
        assert isinstance(channelmanager, ChannelManagerContract)
        self.channelmanager = channelmanager
        self.graph = nx.Graph()  # undirected graph, for bidirectional channels
        self.mk_graph()

    def mk_graph(self):
        for channel in self.channelmanager.nettingcontracts.values():
            assert isinstance(channel, NettingChannelContract)

            first, second = channel.participants.keys()
            assert isaddress(first) and isaddress(second)

            self.graph.add_edge(first, second)

    def get_paths(self, source, target):
        """Compute all shortest paths in the graph.

        Returns:
            generator of lists: A generator of all paths between source and
            target.
        """

        assert isaddress(source) and isaddress(target)
        return nx.all_shortest_paths(self.graph, source, target)

    def get_paths_of_length(self, source, num_hops=1):
        """ Searchs for all nodes that are `num_hops` away.

        Returns:
            list of paths: A list of all shortest paths that have length lenght
            `num_hops + 1`
        """
        # return a dictionary keyed by targets
        # with a list of nodes in a shortest path
        # from the source to one of the targets.
        all_paths = nx.shortest_path(self.graph, source)

        return [
            path
            for path in all_paths.values()
            if len(path) == num_hops + 1
        ]
