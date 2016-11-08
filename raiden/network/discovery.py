# -*- coding: utf-8 -*-
from ethereum import _solidity

from raiden.utils import (
    host_port_to_endpoint,
    isaddress,
    pex,
    split_endpoint,
    get_contract_path,
)
from raiden.network.rpc.client import DEFAULT_POLL_TIMEOUT

discovery_contract_compiled = _solidity.compile_contract(
    get_contract_path('EndpointRegistry.sol'),
    'EndpointRegistry',
    combined='abi',
)
DISCOVERY_CONTRACT_ABI = discovery_contract_compiled['abi']


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
            raise KeyError('Unknown address {}'.format(pex(nodeid)))

    def nodeid_by_host_port(self, host_port):
        for nodeid, value_hostport in self.nodeid_hostport.items():
            if value_hostport == host_port:
                return nodeid
        return None


class ContractDiscovery(Discovery):
    """On chain smart contract raiden node discovery: allows to register endpoints (host, port) for
    your ethereum-/raiden-address and looking up endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(self, node_address, discovery_proxy):
        super(ContractDiscovery, self).__init__()

        self.node_address = node_address
        self.discovery_proxy = discovery_proxy

    def register(self, node_address, host, port):
        if node_address != self.node_address:
            raise ValueError('You can only register your own endpoint.')

        endpoint = host_port_to_endpoint(host, port)
        self.discovery_proxy.register_endpoint(endpoint)

    def get(self, node_address):
        return self.discovery_proxy.endpoint_by_address(node_address)

    def nodeid_by_host_port(self, host_port):
        host, port = host_port
        endpoint = host_port_to_endpoint(host, port)
        return self.discovery_proxy.address_by_endpoint(endpoint)
