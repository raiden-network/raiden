from raiden_service import RaidenProtocol
from utils import isaddress, pex, sha3


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


class UnreliableTransport(Transport):

    "simulate random lost udp messages"

    counter = 0
    droprate = 2  # drop every Nth message

    def send(self, sender, host_port, message):
        for cb in self.on_send_cbs:
            cb(sender, host_port, message)
        print 'in send unreliable', self.counter, self.counter % self.droprate
        self.counter += 1
        if (self.counter - 1) % self.droprate:
            self.protocols[host_port].receive(message)
        else:
            print('dropped message {}'.format(pex(sha3(message))))


class Discovery(object):

    """
    Mock mapping address: host, port
    """

    def __init__(self):
        self.h = dict()

    def register(self, nodeid, host, port):
        assert isaddress(nodeid)  # fixme, this is H(pubkey)
        self.h[nodeid] = (host, port)

    def get(self, nodeid):
        return self.h[nodeid]
