# -*- coding: utf-8 -*-
"""
This module contains the classes responsible to implement the network
communication.
"""
import time

import gevent
from gevent.server import DatagramServer
from ethereum import slogging

from raiden.network.protocol import RaidenProtocol
from raiden.utils import pex, sha3

log = slogging.get_logger('raiden.network.transport')  # pylint: disable=invalid-name


class DummyPolicy(object):
    """Dummy implementation for the throttling policy that always
    returns a wait_time of 0.
    """
    def __init__(self):
        pass

    def consume(self, tokens):
        return 0.


class TokenBucket(object):
    """Implementation of the token bucket throttling algorithm.
    """

    def __init__(self, capacity=10., fill_rate=10.):
        self.capacity = float(capacity)
        self.fill_rate = fill_rate
        self.tokens = float(capacity)
        self.timestamp = time.time()

    def consume(self, tokens):
        """Consume tokens.
        Args:
            tokens (float): number of transport tokens to consume
        Returns:
            wait_time (float): waiting time for the consumer
        """
        wait_time = 0.
        self.tokens -= tokens
        if self.tokens < 0:
            self._get_tokens()
        if self.tokens < 0:
            wait_time = -self.tokens / self.fill_rate
        return wait_time

    def _get_tokens(self):
        now = time.time()
        self.tokens += self.fill_rate * (now - self.timestamp)
        if self.tokens > self.capacity:
            self.tokens = self.capacity
        self.timestamp = now


class UDPTransport(object):
    """ Node communication using the UDP protocol. """

    def __init__(
            self,
            host,
            port,
            socket=None,
            protocol=None,
            throttle_policy=DummyPolicy()):

        self.protocol = protocol
        if socket is not None:
            self.server = DatagramServer(socket, handle=self.receive)
        else:
            self.server = DatagramServer((host, port), handle=self.receive)
        self.server.start()
        self.host = self.server.server_host
        self.port = self.server.server_port
        self.throttle_policy = throttle_policy

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
        gevent.sleep(self.throttle_policy.consume(1))
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

    def __init__(
            self,
            host,
            port,
            protocol=None,
            throttle_policy=DummyPolicy()):

        self.host = host
        self.port = port
        self.protocol = protocol

        self.network.register(self, host, port)
        self.throttle_policy = throttle_policy

    def send(self, sender, host_port, bytes_):
        gevent.sleep(self.throttle_policy.consume(1))
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
        # even dropped packages have to go through throttle_policy
        gevent.sleep(self.throttle_policy.consume(1))
        drop = bool(self.network.counter % self.droprate == 0)

        if not drop:
            self.network.send(sender, host_port, bytes_)
        else:
            # since this path wont go to super.send we need to call track
            # ourselves
            self.network.track_send(sender, host_port, bytes_)

            log.debug(
                'dropped packet',
                counter=self.network.counter,
                msghash=format(pex(sha3(bytes_)))
            )
