# -*- coding: utf-8 -*-
import networkx

from raiden.utils import isaddress


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

    def __init__(self, edge_list):
        """
        Args:
            edge_list (List[(address1, address2)]): all the netting contracts
                that participate in the network.
        """
        self.graph = make_graph(edge_list)

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

    def has_path(self, source, target):
        """ Return True if there is a path connecting source and target, False
        otherwise.
        """
        return networkx.has_path(self.graph, source, target)

    def add_path(self, from_, to_):
        """ Add a new edge into the network. """
        self.graph.add_edge(from_, to_)

    def remove_path(self, from_, to_):
        """ Remove an edge from the network. """
        self.graph.remove_edge(from_, to_)
