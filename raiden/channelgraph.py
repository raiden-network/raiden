# -*- coding: utf8 -*-
import networkx

from raiden.blockchain.net_contract import NettingChannelContract
from raiden.utils import isaddress


def make_graph(netting_contracts):
    """ Return a graph that represents the connections among the netting
    contracts.

    Args:
        nettingcontracts (List[NettingChannelContract]): all the netting
            contracts that participate in the network.

    Returns:
        Graph A networkx.Graph instance were the graph nodes are nodes in the
            network and the edges are nodes that have a channel between them.
    """
    graph = networkx.Graph()  # undirected graph, for bidirectional channels

    for channel in netting_contracts:
        assert isinstance(channel, NettingChannelContract)

        first, second = channel.participants.keys()
        assert isaddress(first) and isaddress(second)

        graph.add_edge(first, second)

    return graph


class ChannelGraph(object):
    """ Has Graph based on the channels and can find path between participants. """

    def __init__(self, netting_contracts):
        """
        Args:
            netting_contracts (List[NettingChannelContract]): All the channels
                that compose the graph.
        """
        self.netting_contracts = netting_contracts
        self.graph = make_graph(netting_contracts)

    def get_paths(self, source, target):
        """Compute all shortest paths in the graph.

        Returns:
            generator of lists: A generator of all paths between source and
            target.
        """

        assert isaddress(source) and isaddress(target)
        return networkx.all_shortest_paths(self.graph, source, target)

    def get_paths_of_length(self, source, num_hops=1):
        """ Searchs for all nodes that are `num_hops` away.

        Returns:
            list of paths: A list of all shortest paths that have length lenght
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
