#!/usr/bin/env python
from __future__ import print_function

import os
import json

from ethereum._solidity import compile_contract
from ethereum.utils import decode_hex
from pyethapp.rpc_client import JSONRPCClient
from pyethapp.jsonrpc import default_gasprice
from raiden.utils import get_contract_path
from raiden.network.rpc.client import patch_send_transaction, patch_send_message


# ordered list of solidity files to deploy for the raiden registry
RAIDEN_CONTRACT_FILES = [
    'Token.sol',
    'NettingChannelLibrary.sol',
    'ChannelManagerLibrary.sol',
    'Registry.sol',
]
DISCOVERY_CONTRACT_FILES = ['EndpointRegistry.sol']


def name_from_file(filename):
    return os.path.split(filename)[-1].split('.')[0]


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
            contract_path=c,
            gasprice=default_gasprice
        )
        libraries[name] = proxy.address
    return {name: addr.encode('hex') for name, addr in libraries.items()}


def deploy_all(client):
    patch_send_transaction(client)
    patch_send_message(client)
    deployed = dict()
    deployed.update(deploy_files(RAIDEN_CONTRACT_FILES, client))
    deployed.update(deploy_files(DISCOVERY_CONTRACT_FILES, client))
    return deployed


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int)
    parser.add_argument('privatekey')
    parser.add_argument('--pretty', default=False, action='store_true')
    args = parser.parse_args()

    port = args.port
    privatekey_hex = args.privatekey
    privatekey = decode_hex(privatekey_hex)

    pretty = False
    client = JSONRPCClient(
        port=port,
        privkey=privatekey,
        print_communication=False,
    )
    patch_send_transaction(client)
    patch_send_message(client)
    deployed = deploy_all(client)

    if args.pretty:
        indent = 2
    else:
        indent = None

    print(json.dumps(deployed, indent=indent))
