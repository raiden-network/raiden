#!/usr/bin/env python
from __future__ import print_function

import json
import os

import click
import logging
from ethereum import slogging
from ethereum._solidity import compile_contract
from ethereum.utils import decode_hex
from pyethapp.rpc_client import JSONRPCClient

from raiden.network.rpc.client import patch_send_message, patch_send_transaction
from raiden.settings import GAS_PRICE
from raiden.utils import get_contract_path


log = slogging.getLogger(__name__)


# Source files for all to be deployed solidity contracts
RAIDEN_CONTRACT_FILES = [
    'NettingChannelLibrary.sol',
    'ChannelManagerLibrary.sol',
    'Registry.sol',
    'EndpointRegistry.sol'
]

# Top level contracts to be deployed. Dependencies are handled automatically
# in `JSONRPCClient.deploy_solidity_contract()`
CONTRACTS_TO_DEPLOY = [
    'Registry.sol:Registry',
    'EndpointRegistry.sol:EndpointRegistry'
]


def patch_deploy_solidity_contract():
    """
    Patch `JSONRPCClient.deploy_solidity_contract()` to not create a copy of
    the `libraries` dict parameter by removing the assignment in
    `pyethapp.rpc_client.py:251` via AST manipulation.

    This allows us to access the addresses of the deployed dependencies until
    PyEthApp issue #244 is fixed (https://github.com/ethereum/pyethapp/issues/244)
    """

    import ast
    from ast import NodeTransformer
    from inspect import getsource, getsourcefile
    from textwrap import dedent

    class RemoveLibraryDeref(NodeTransformer):
        """
        Removes the AST node representing the line
        `    libraries = dict(libraries)`
        """
        def visit_Assign(self, node):
            if (
                len(node.targets) == 1 and
                isinstance(node.targets[0], ast.Name) and
                node.targets[0].id == 'libraries'
            ):
                return None
            return node
    ast_ = ast.parse(dedent(getsource(JSONRPCClient.deploy_solidity_contract)))
    ast_ = RemoveLibraryDeref().visit(ast_)
    code = compile(ast_, getsourcefile(JSONRPCClient.deploy_solidity_contract), 'exec')
    ctx = {}
    exec(code, JSONRPCClient.deploy_solidity_contract.im_func.__globals__, ctx)
    JSONRPCClient.deploy_solidity_contract = ctx['deploy_solidity_contract']


def name_from_file(filename):
    return os.path.split(filename)[-1].partition('.')[0]


def allcontracts(contract_files):
    return {
        "{}:{}".format(c, name_from_file(c)): compile_contract(
            get_contract_path(c),
            name_from_file(c),
            optimize=False
        )
        for c in contract_files
    }


def deploy_file(contract, compiled_contracts, client, gas_price=GAS_PRICE):
    libraries = dict()
    filename, _, name = contract.partition(":")
    log.info("Deploying %s", name)
    proxy = client.deploy_solidity_contract(
        client.sender,
        name,
        compiled_contracts,
        libraries,
        '',
        contract_path=filename,
        gasprice=gas_price
    )
    log.info("Deployed %s @ 0x%s", name, proxy.address.encode('hex'))
    libraries[contract] = proxy.address.encode('hex')
    return libraries


def deploy_all(client, gas_price=GAS_PRICE):
    compiled_contracts = allcontracts(RAIDEN_CONTRACT_FILES)
    deployed = {}
    for contract in CONTRACTS_TO_DEPLOY:
        deployed.update(deploy_file(contract, compiled_contracts, client, gas_price))
    return deployed


@click.command(help="Deploy the Raiden smart contracts.\n\n"
                    "Requires the private key to an account with enough balance to deploy all "
                    "four contracts.")
@click.option("--pretty", is_flag=True)
@click.option("--gas-price", default=4, help="Gas price to use in GWei", show_default=True)
@click.option("--port", type=int, default=8545, show_default=True)
@click.argument("privatekey_hex")
def main(privatekey_hex, pretty, gas_price, port):
    slogging.configure(":debug")
    # Fix pyethapp.rpc_client not using slogging library
    rpc_logger = logging.getLogger('pyethapp.rpc_client')
    rpc_logger.setLevel(logging.DEBUG)
    rpc_logger.parent = slogging.getLogger()

    privatekey = decode_hex(privatekey_hex)

    patch_deploy_solidity_contract()
    client = JSONRPCClient(
        port=port,
        privkey=privatekey,
        print_communication=False,
    )
    patch_send_transaction(client)
    patch_send_message(client)

    deployed = deploy_all(client, gas_price)
    print(json.dumps(deployed, indent=2 if pretty else None))


if __name__ == "__main__":
    main()
