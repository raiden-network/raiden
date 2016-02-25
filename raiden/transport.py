# -*- coding: utf8 -*-
import gevent
from ethereum import slogging
from gevent.server import DatagramServer

from raiden_service import RaidenProtocol
from utils import isaddress, pex, sha3

log = slogging.get_logger('transport')


class UDPTransport(object):

    def __init__(self, host, port, protocol=None):
        self.protocol = protocol
        self.server = DatagramServer((host, port), handle=self.receive)
        self.server.start()
        self.host = self.server.server_host
        self.port = self.server.server_port

    def receive(self, data, host_port):
        self.protocol.receive(data)

    def send(self, sender, host_port, data):
        log.info('TRANSPORT SENDS')
        self.server.sendto(data, host_port)
        DummyTransport.network.track_send(sender, host_port, data)  # debuging

    def register(self, proto, host, port):
        assert isinstance(proto, RaidenProtocol)
        self.protocol = proto


class DummyNetwork(object):

    "global which connects the DummyTransports"

    on_send_cbs = []  # debugging

    def __init__(self):
        self.transports = dict()
        self.counter = 0

    def register(self, transport, host, port):
        assert isinstance(transport, DummyTransport)
        self.transports[(host, port)] = transport

    def track_send(self, sender, host_port, data):
        self.counter += 1
        for cb in self.on_send_cbs:
            cb(sender, host_port, data)

    def send(self, sender, host_port, data):
        self.track_send(sender, host_port, data)
        f = self.transports[host_port].receive
        gevent.spawn_later(0.00000000001, f, data)

    def drop(self, sender, host_port, data):
        "lost message"
        self.counter += 1
        for cb in self.on_send_cbs:
            cb(sender, host_port, data)


class DummyTransport(object):
    network = DummyNetwork()
    on_recv_cbs = []  # debugging

    def __init__(self, host, port, protocol=None):
        self.protocol = protocol
        self.host, self.port = host, port
        self.network.register(self, host, port)

    def send(self, sender, host_port, data):
        log.info('TRANSPORT SENDS')
        self.network.send(sender, host_port, data)

    def track_recv(self, data, host_port=None):
        for cb in self.on_recv_cbs:
            cb(self.protocol.raiden, host_port, data)

    def receive(self, data, host_port=None):
        self.track_recv(data, host_port)
        self.protocol.receive(data)


class UnreliableTransport(DummyTransport):

    "simulate random lost udp messages"

    droprate = 2  # drop every Nth message

    def send(self, sender, host_port, data):
        log.debug('in send unreliable', counter=self.network.counter,
                  drop_this_one=not(self.network.counter % self.droprate))

        if self.network.counter % self.droprate:
            self.network.send(sender, host_port, data)
        else:
            self.network.track_send(sender, host_port, data)
            log.debug('dropped', data=format(pex(sha3(data))))


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

    def nodeid_by_host_port(self, host_port):
        for k, v in self.h:
            if v == host_port:
                return k
        assert False
