import networkx as nx
from raiden.contracts import ChannelManagerContract, NettingChannelContract
from raiden.utils import isaddress


class ChannelGraph(object):

    """
    Has Graph based on the channels and can find path between participants
    """

    def __init__(self, contract):
        assert isinstance(contract, ChannelManagerContract)
        self.contract = contract
        self.G = nx.Graph()  # undirected graph, for bidirectional channels
        self.mk_graph()

    def mk_graph(self):
        for c in self.contract.channels:
            assert isinstance(c, NettingChannelContract)
            a, b = c.participants.keys()
            assert isaddress(a) and isaddress(b)
            self.G.add_edge(a, b)

    def get_paths(self, source, target):
        assert isaddress(source) and isaddress(target)
        return nx.all_shortest_paths(self.G, source, target)
