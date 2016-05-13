# -*- coding: utf8 -*-
from ethereum import _solidity
from pyethapp.rpc_client import JSONRPCClient

solidity = _solidity.get_solidity()

def get_abi_from_file(filename):
    with open(filename) as handler:
        code = handler.read()
        return solidity.mk_full_signature(code)


def get_proxies(privkey, port):
    channel_manager_abi = get_abi_from_file('channelManagerContract.sol')
    netting_contract_abi = get_abi_from_file('nettingChannelContract.sol')
    registry_abi = get_abi_from_file('registry.sol')

    client = JSONRPCClient(port=port, privkey=privkey)

    channel_manager_proxy = client.new_abi_contract(channel_manager_abi, channel_manager_address)
    registry_proxy = client.new_abi_contract(registry_abi, registry_address)
    netting_contract_proxy = client.new_abi_contract(netting_contract_abi, netting_contract_address)

    return channel_manager_proxy, registry_proxy, netting_contract_proxy
