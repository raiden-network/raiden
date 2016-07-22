# -*- coding: utf8 -*-
from raiden.utils import isaddress, pex
from raiden.blockchain.abi import get_contract_path
from ethereum import _solidity

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

        assert False


class ContractDiscovery(Discovery):
    """
    This is the place where ethereum addresses are registered to their network sockets
    """
    def __init__(self, rpc_client, discovery_contract_address):
        self.discovery_proxy = rpc_client.new_abi_contract(
            DISCOVERY_CONTRACT_ABI,
            discovery_contract_address.encode('hex'),
        )

    def register_endpoint(self, host, port):
        self.discovery_proxy.registerEndpoint(''.join([host, ':', port]))

    def update_endpoint(self, host, port):
        self.discovery_proxy.updateEndpoint(''.join([host, ':', port]))

    def find_endpoint(self, nodeid):
        return self.discovery_proxy.findEndpointByAddress(nodeid.encode('hex'))

    def find_address(self, host, port):
        return self.discovery_proxy.findAddressByEndpoint(''.join([host, ':', port]))
