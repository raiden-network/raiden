# -*- coding: utf-8 -*-
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

    def register(self, nodeid, host, port):
        assert isaddress(nodeid)  # fixme, this is H(pubkey)
        self.nodeid_hostport[nodeid] = (host, port)

    def get(self, nodeid):
        try:
            return self.nodeid_hostport[nodeid]
        except KeyError:
            raise InvalidAddress('Unknown address {}'.format(pex(nodeid)))

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
