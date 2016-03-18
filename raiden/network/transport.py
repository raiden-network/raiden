# -*- coding: utf8 -*-
'''
This module contains the classes responsable to implement the network
communication.
'''
import gevent
from gevent.server import DatagramServer
from ethereum import slogging

from raiden.raiden_service import RaidenProtocol
from raiden.utils import pex, sha3, privtoaddr, isaddress

log = slogging.get_logger('raiden.network.transport')  # pylint: disable=invalid-name


class UDPTransport(object):
    ''' Node communication using the UDP protocol. '''

    def __init__(self, host, port, protocol=None):
        self.protocol = protocol
        self.server = DatagramServer((host, port), handle=self.receive)
        self.server.start()
        self.host = self.server.server_host
        self.port = self.server.server_port

    def receive(self, data, host_port):  # pylint: disable=unused-argument
        self.protocol.receive(data)

    def send(self, sender, host_port, data):
        self.server.sendto(data, host_port)

        # enable debugging using the DummyNetwork callbacks
        DummyTransport.network.track_send(sender, host_port, data)

    def register(self, proto, host, port):  # pylint: disable=unused-argument
        assert isinstance(proto, RaidenProtocol)
        self.protocol = proto


class DummyNetwork(object):
    ''' Store global state for an in process network, this won't use a real
    network protocol just greenlet communication.

    Note:
        Useful for debugging purposes.
    '''

    on_send_cbs = []  # debugging

    def __init__(self):
        self.transports = dict()
        self.counter = 0

    def register(self, transport, host, port):
        ''' Register a new node in the dummy network. '''
        assert isinstance(transport, DummyTransport)
        self.transports[(host, port)] = transport

    def track_send(self, sender, host_port, data):
        self.counter += 1
        for callback in self.on_send_cbs:
            callback(sender, host_port, data)

    def send(self, sender, host_port, data):
        self.track_send(sender, host_port, data)
        receive_end = self.transports[host_port].receive

        gevent.spawn_later(0.00000000001, receive_end, data)

    def drop(self, sender, host_port, data):
        self.counter += 1
        for callback in self.on_send_cbs:
            callback(sender, host_port, data)


class DummyTransport(object):
    ''' Communication between inter-process nodes.

    Note:
        Useful for debugging purposes.
    '''
    network = DummyNetwork()
    on_recv_cbs = []  # debugging

    def __init__(self, host, port, protocol=None):
        self.protocol = protocol
        self.host, self.port = host, port
        self.network.register(self, host, port)

    def send(self, sender, host_port, data):
        self.network.send(sender, host_port, data)

    def track_recv(self, data, host_port=None):
        for callback in self.on_recv_cbs:
            callback(self.protocol.raiden, host_port, data)

    def receive(self, data, host_port=None):
        self.track_recv(data, host_port)
        self.protocol.receive(data)


class UnreliableTransport(DummyTransport):
    ''' A transport that simulates random loses of UDP messages.

    Note:
        Useful for debugging purposes.
    '''

    droprate = 2  # drop every Nth message

    def send(self, sender, host_port, data):
        drop = bool(self.network.counter % self.droprate)

        log.debug(
            'in send unreliable',
            counter=self.network.counter,
            drop_this_one=drop,
        )

        if not drop:
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


class PredictiveDiscovery(Discovery):
    """
    Initialized with a list of `(host, num_nodes, start_port)` tuples,
    this discovery is able to predict the address for any
    (predictable) node-id.

    This avoids the need of a shared discovery instance, while still
    providing the convenience of a mock-like service.

    Note, that start_port can be omitted.
    """
    def __init__(self, mapping, default_start_port=40001):
        self.h = dict()
        # [('127.0.0.1', 36), ('127.0.0.2', 15), ...]
        for entry in mapping:
            if len(entry) == 3:
                start_port = entry.pop()
            else:
                start_port = default_start_port
            (host, num_nodes) = entry
            for i in range(num_nodes):
                host_port = (host, start_port + i)
                self.h[privtoaddr(sha3("{}:{}".format(*host_port)))] = host_port

    def register(self, *args):
        # noop
        pass
