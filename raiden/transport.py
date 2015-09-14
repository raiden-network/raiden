from raiden_service import RaidenProtocol
from utils import isaddress


class Transport(object):

    def __init__(self):
        self.protocols = dict()
        self.on_send_cbs = []  # debugging

    def send(self, sender, host_port, message):
        for cb in self.on_send_cbs:
            cb(sender, host_port, message)
        self.protocols[host_port].receive(message)

    def register(self, proto, host, port):
        assert isinstance(proto, RaidenProtocol)
        self.protocols[(host, port)] = proto


class Discovery(object):

    """
    Mock mapping nodeid: host, port
    """

    def __init__(self):
        self.h = dict()

    def register(self, nodeid, host, port):
        assert isaddress(nodeid)  # fixme, this is H(pubkey)
        self.h[nodeid] = (host, port)

    def get(self, nodeid):
        return self.h[nodeid]
