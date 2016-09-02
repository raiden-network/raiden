#!/usr/bin/env python
import os
import json
from ethereum._solidity import compile_contract
from ethereum.utils import denoms
from pyethapp.rpc_client import JSONRPCClient
from raiden.blockchain.abi import get_contract_path
from raiden.network.rpc.client import patch_send_transaction


# ordered list of solidity files to deploy for the raiden registry
RAIDEN_CONTRACT_FILES = ["Token.sol", "NettingChannelLibrary.sol", "ChannelManagerLibrary.sol", "Registry.sol"]
DISCOVERY_CONTRACT_FILES = ["EndpointRegistry.sol"]

name_from_file = lambda fn: os.path.split(fn)[-1].split('.')[0]


def allcontracts(contract_files):
    return {
        name_from_file(c): compile_contract(
            get_contract_path(c),
            name_from_file(c)) for c in contract_files
    }


def deploy_files(contract_files, client):
    compiled_contracts = allcontracts(contract_files)
    libraries = dict()
    for c in contract_files:
        name = name_from_file(c)
        proxy = client.deploy_solidity_contract(
            client.sender,
            name,
            compiled_contracts,
            libraries,
            '',
            gasprice=denoms.shannon * 20
        )
        libraries[name] = proxy.address
    return {name: addr.encode('hex') for name, addr in libraries.items()}


def deploy_all(client):
    patch_send_transaction(client)
    deployed = dict()
    deployed.update(deploy_files(RAIDEN_CONTRACT_FILES, client))
    deployed.update(deploy_files(DISCOVERY_CONTRACT_FILES, client))
    return deployed


if __name__ == "__main__":
    # FIXME: client params should be read from cmdline-args!
    pretty = False
    client = JSONRPCClient(port=8545,
                           privkey='1' * 64,
                           print_communication=False,
                           )
    patch_send_transaction(client)
    deployed = deploy_all(client)
    print json.dumps(deployed, indent=2 if pretty else None)
