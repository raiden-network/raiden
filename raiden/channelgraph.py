import networkx as nx
from raiden.contracts import ChannelManagerContract, NettingChannelContract
from raiden.utils import isaddress


class ChannelGraph(object):

    """
    Has Graph based on the channels and can find path between participants
    """

    def __init__(self, channelmanager):
        assert isinstance(channelmanager, ChannelManagerContract)
        self.channelmanager = channelmanager
        self.G = nx.Graph()  # undirected graph, for bidirectional channels
        self.mk_graph()

    def mk_graph(self):
        for c in self.channelmanager.nettingcontracts.values():
            assert isinstance(c, NettingChannelContract)
            a, b = c.participants.keys()
            assert isaddress(a) and isaddress(b)
            self.G.add_edge(a, b)

    def get_paths(self, source, target):
        assert isaddress(source) and isaddress(target)
        return nx.all_shortest_paths(self.G, source, target)

    def get_paths_of_length(self, source, num_hops=1):
        """
        shortest_path

        """
        # return a dictionary keyed by targets
        # with a list of nodes in a shortest path
        # from the source to one of the targets.
        paths = nx.shortest_path(self.G, source)
        return [p for p in paths.values() if len(p) == num_hops + 1]
