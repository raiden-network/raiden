# -*- coding: utf-8 -*-
"""
This module contains the classes responsible to implement the network
communication.
"""
import gevent
from gevent.server import DatagramServer
from ethereum import slogging

from raiden.network.protocol import RaidenProtocol
from raiden.utils import pex, sha3

log = slogging.get_logger('raiden.network.transport')  # pylint: disable=invalid-name


class UDPTransport(object):
    """ Node communication using the UDP protocol. """

    def __init__(self, host, port, protocol=None):
        self.protocol = protocol
        self.server = DatagramServer((host, port), handle=self.receive)
        self.server.start()
        self.host = self.server.server_host
        self.port = self.server.server_port

    def receive(self, data, host_port):  # pylint: disable=unused-argument
        self.protocol.receive(data)

        # enable debugging using the DummyNetwork callbacks
        DummyTransport.track_recv(self.protocol.raiden, host_port, data)

    def send(self, sender, host_port, bytes_):
        """ Send `bytes_` to `host_port`.

        Args:
            sender (address): The address of the running node.
            host_port (Tuple[(str, int)]): Tuple with the host name and port number.
            bytes_ (bytes): The bytes that are going to be sent through the wire.
        """
        self.server.sendto(bytes_, host_port)

        # enable debugging using the DummyNetwork callbacks
        DummyTransport.network.track_send(sender, host_port, bytes_)

    def register(self, proto, host, port):  # pylint: disable=unused-argument
        assert isinstance(proto, RaidenProtocol)
        self.protocol = proto

    def stop(self):
        self.server.stop()


class DummyNetwork(object):
    """ Store global state for an in process network, this won't use a real
    network protocol just greenlet communication.
    """

    on_send_cbs = []  # debugging

    def __init__(self):
        self.transports = dict()
        self.counter = 0

    def register(self, transport, host, port):
        """ Register a new node in the dummy network. """
        assert isinstance(transport, DummyTransport)
        self.transports[(host, port)] = transport

    def track_send(self, sender, host_port, bytes_):
        """ Register an attempt to send a packet. This method should be called
        everytime send() is used.
        """
        self.counter += 1
        for callback in self.on_send_cbs:
            callback(sender, host_port, bytes_)

    def send(self, sender, host_port, bytes_):
        self.track_send(sender, host_port, bytes_)
        receive_end = self.transports[host_port].receive
        gevent.spawn_later(0.00000000001, receive_end, bytes_)


class DummyTransport(object):
    """ Communication between inter-process nodes. """
    network = DummyNetwork()
    on_recv_cbs = []  # debugging

    def __init__(self, host, port, protocol=None):
        self.host = host
        self.port = port
        self.protocol = protocol

        self.network.register(self, host, port)

    def send(self, sender, host_port, bytes_):
        self.network.send(sender, host_port, bytes_)

    @classmethod
    def track_recv(cls, raiden, host_port, data):
        for callback in cls.on_recv_cbs:
            callback(raiden, host_port, data)

    def receive(self, data, host_port=None):
        self.track_recv(self.protocol.raiden, host_port, data)
        self.protocol.receive(data)

    def stop(self):
        pass


class UnreliableTransport(DummyTransport):
    """ A transport that simulates random losses of UDP messages. """

    droprate = 2  # drop every Nth message

    def send(self, sender, host_port, bytes_):
        drop = bool(self.network.counter % self.droprate == 0)

        if not drop:
            self.network.send(sender, host_port, bytes_)
        else:
            # since this path wont go to super.send we need to call track
            # ourselves
            self.network.track_send(sender, host_port, bytes_)

            log.debug(
                'dropped packed',
                counter=self.network.counter,
                data=format(pex(sha3(bytes_)))
            )
