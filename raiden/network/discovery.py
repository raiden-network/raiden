# -*- coding: utf-8 -*-
import socket

from raiden.utils import (
    host_port_to_endpoint,
    isaddress,
    pex,
    split_endpoint,
)
from raiden.exceptions import InvalidAddress


class Discovery(object):
    """ Mock mapping address: host, port """

    def __init__(self):
        self.nodeid_hostport = dict()

    def register(self, node_address, host, port):
        if not isaddress(node_address):
            raise ValueError('node_address must be a valid address')

        try:
            socket.inet_pton(socket.AF_INET, host)
        except OSError:
            raise ValueError('invalid ip address provided: {}'.format(host))

        if not isinstance(port, (int, long)):
            raise ValueError('port must be a valid number')

        self.nodeid_hostport[node_address] = (host, port)

    def get(self, node_address):
        try:
            return self.nodeid_hostport[node_address]
        except KeyError:
            raise InvalidAddress('Unknown address {}'.format(pex(node_address)))

    def nodeid_by_host_port(self, host_port):
        for nodeid, value_hostport in self.nodeid_hostport.items():
            if value_hostport == host_port:
                return nodeid
        return None


class ContractDiscovery(Discovery):
    """ Raiden node discovery.

    Allows registering and looking up by endpoint (host, port) for node_address.
    """

    def __init__(self, node_address, discovery_proxy):
        super(ContractDiscovery, self).__init__()

        self.node_address = node_address
        self.discovery_proxy = discovery_proxy

    def register(self, node_address, host, port):
        if node_address != self.node_address:
            raise ValueError('You can only register your own endpoint.')

        if not isaddress(node_address):
            raise ValueError('node_address must be a valid address')

        try:
            socket.inet_pton(socket.AF_INET, host)
        except OSError:
            raise ValueError('invalid ip address provided: {}'.format(host))

        if not isinstance(port, (int, long)):
            raise ValueError('port must be a valid number')

        endpoint = host_port_to_endpoint(host, port)
        self.discovery_proxy.register_endpoint(node_address, endpoint)

    def get(self, node_address):
        endpoint = self.discovery_proxy.endpoint_by_address(node_address)
        host_port = split_endpoint(endpoint)
        return host_port

    def nodeid_by_host_port(self, host_port):
        host, port = host_port
        endpoint = host_port_to_endpoint(host, port)
        return self.discovery_proxy.address_by_endpoint(endpoint)
