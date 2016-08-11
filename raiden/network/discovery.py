# -*- coding: utf8 -*-
from ethereum import _solidity

from raiden.utils import (
    host_port_to_endpoint,
    isaddress,
    pex,
    split_endpoint,
)
from raiden.blockchain.abi import get_contract_path

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
            raise KeyError('Unknow address {}'.format(pex(nodeid)))

    def nodeid_by_host_port(self, host_port):
        for nodeid, value_hostport in self.nodeid_hostport.items():
            if value_hostport == host_port:
                return nodeid
        return None


class ContractDiscovery(Discovery):
    """On chain smart contract raiden node discovery: allows to register endpoints (host, port) for
    your ethereum-/raiden-address and looking up endpoints for other ethereum-/raiden-addressess.
    """
    def __init__(self, rpc_client, discovery_contract_address):
        self.discovery_proxy = rpc_client.new_abi_contract(
            DISCOVERY_CONTRACT_ABI,
            discovery_contract_address.encode('hex'),
        )

    def register(self, nodeid, host, port):
        assert isaddress(nodeid)
        self.discovery_proxy.registerEndpoint(host_port_to_endpoint(host, port))

    def get(self, nodeid):
        # check whether to encode or decode nodeid
        endpoint = self.discovery_proxy.findEndpointByAddress(nodeid.encode('hex'))
        if endpoint is '':
            raise KeyError('Unknow address {}'.format(pex(nodeid)))
        return split_endpoint(endpoint)

    def nodeid_by_host_port(self, host_port):
        host, port = host_port
        address = self.discovery_proxy.findAddressByEndpoint(host_port_to_endpoint(host, port))
        # the 0 address means nothing found
        if set(address) == {'0'}:
            return None
        return address.decode('hex')
