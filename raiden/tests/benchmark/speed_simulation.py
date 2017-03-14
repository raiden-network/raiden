# -*- coding: utf-8 -*-
"""
A benchmark script to configure a test network and execute random Raiden
transactions.
"""
from __future__ import print_function

import codecs
import random
import signal
import sys

import yaml
import gevent
import networkx

from raiden.settings import DEFAULT_SETTLE_TIMEOUT
from raiden.app import App
from raiden.network.discovery import Discovery
from raiden.network.rpc.client import BlockChainService
from raiden.utils import sha3, privatekey_to_address

TRANSFER_AMOUNT = 1
TOKEN_ADDRESS = sha3('tps')[:20]


def hostport_to_privkeyaddr(host, port):
    """ Return `(private key, address)` deterministically generated. """
    myip_port = '{}:{}'.format(host, port)
    privkey = sha3(myip_port)
    addr = privatekey_to_address(privkey)

    return privkey, addr


def random_raiden_network(
        token_address,
        blockchain_service,
        node_addresses,
        deposit,
        settle_timeout
):
    """ Creates random channels among the test nodes until we have a connected graph. """
    graph = networkx.Graph()
    graph.add_nodes_from(node_addresses)

    for edge in blockchain_service.addresses_by_token(token_address):
        graph.add_edge(edge[0], edge[1])

    while not networkx.is_connected(graph):
        from_address = random.choice(node_addresses)
        to_address = random.choice(node_addresses)

        netcontract_address = blockchain_service.new_netting_contract(
            token_address,
            from_address,
            to_address,
            settle_timeout,
        )

        blockchain_service.deposit(
            token_address,
            netcontract_address,
            from_address,
            deposit,
        )

        blockchain_service.deposit(
            token_address,
            netcontract_address,
            to_address,
            deposit,
        )

        graph.add_edge(from_address, to_address)


def setup_tps(
        rpc_server,
        config_path,
        channelmanager_address,
        token_address,
        deposit,
        settle_timeout
):
    """ Creates the required contract and the fully connected Raiden network
    prior to running the test.

    Args:
        rpc_server (str): A string in the format '{host}:{port}' used to define
            the JSON-RPC end-point.
        config_path (str): A full/relative path to the yaml configuration file.
        channelmanager_address (str): The address of the channel manager contract.
        token_address (str): The address of the token used for testing.
        deposit (int): The default deposit that will be made for all test nodes.
    """
    # TODO:
    #  - create/register the channel manager

    rpc_connection = rpc_server.split(':')
    rpc_connection = (rpc_connection[0], int(rpc_connection[1]))

    blockchain_service = BlockChainService(rpc_connection, channelmanager_address)
    blockchain_service.new_channel_manager_contract(token_address=token_address)

    with codecs.open(config_path, encoding='utf8') as handler:
        config = yaml.load(handler)

    node_addresses = []
    for node in config['nodes']:
        privkey = sha3('{}:{}'.format(node['host'], node['port']))
        node_addresses.append(privatekey_to_address(privkey))

    random_raiden_network(
        token_address,
        blockchain_service,
        node_addresses,
        deposit,
        settle_timeout,
    )


def random_transfer(app, token, transfer_amount):
    channelgraph = app.raiden.token_managers[token].channelgraph

    nodes = channelgraph.graph.nodes()
    nodes.remove(app.raiden.address)

    while True:
        target = random.choice(nodes)
        app.raiden.api.transfer(token, transfer_amount, target)


def tps_run(
        host,
        port,
        config,
        rpc_server,
        channelmanager_address,
        token_address,
        transfer_amount,
        parallel
):
    # pylint: disable=too-many-locals,too-many-arguments
    ourprivkey, _ = hostport_to_privkeyaddr(host, port)

    rpc_connection = rpc_server.split(':')
    rpc_connection = (rpc_connection[0], int(rpc_connection[1]))

    with codecs.open(config, encoding='utf8') as handler:
        config = yaml.load(handler)

    config['host'] = host
    config['port'] = port
    config['privkey'] = ourprivkey

    blockchain_service = BlockChainService(rpc_server, channelmanager_address)

    discovery = Discovery()
    found_ouraddress = False
    for node in config['nodes']:
        _, address = hostport_to_privkeyaddr(node['host'], node['port'])

        discovery.register(address, node['host'], node['port'])

        if host == node['host'] and str(port) == node['port']:
            found_ouraddress = True

    if not found_ouraddress:
        print('We are not registered in the configuration file')
        sys.exit(1)

    app = App(config, blockchain_service, discovery)

    for token_address in blockchain_service.token_addresses:
        all_netting_contracts = blockchain_service.nettingaddresses_by_token_participant(
            token_address,
            app.raiden.address,
        )

        for netting_contract_address in all_netting_contracts:
            app.raiden.setup_channel(
                token_address,
                netting_contract_address,
                app.config['reveal_timeout'],
            )

    for _ in range(parallel):
        gevent.spawn(random_transfer, app, token_address, transfer_amount)

    # wait for interrupt
    event = gevent.event.Event()
    gevent.signal(signal.SIGQUIT, event.set)
    gevent.signal(signal.SIGTERM, event.set)
    gevent.signal(signal.SIGINT, event.set)
    event.wait()

    app.stop()


def main():
    import argparse
    import os

    # Let the user choose a seed. This won't ensure reproducibility regarding
    # the node's balances, because of the tranfer's timming, but it will
    # generate the same network.
    if 'PYTHONHASHSEED' not in os.environ:
        raise Exception(
            'Please set up the PYTHONHASHSEED variable to ensure a reproducible execution'
        )

    parser = argparse.ArgumentParser()

    kind_parser = parser.add_subparsers(dest='kind')
    runparser = kind_parser.add_parser('run', help='run a single test node')
    setupparser = kind_parser.add_parser(
        'setup',
        help='setup the network, creating the required channels',
    )

    setupparser.add_argument('rpc_server')
    setupparser.add_argument('config')
    setupparser.add_argument('channelmanager_address')

    runparser.add_argument('rpc_server')
    runparser.add_argument('config')
    runparser.add_argument('channelmanager_address')
    runparser.add_argument('host')
    runparser.add_argument('port')
    runparser.add_argument(
        '--parallel',
        type=int,
        default=20,
        help='Number of parallel transfers that will happen for a given node',
    )

    args = parser.parse_args()

    if args.kind == 'run':
        tps_run(
            args.host,
            args.port,
            args.config,
            args.rpc_server,
            args.channelmanager_address,
            TOKEN_ADDRESS,
            TRANSFER_AMOUNT,
            args.parallel,
        )
    elif args.kind == 'setup':
        deposit = 200
        setup_tps(
            args.rpc_server,
            args.config,
            args.channelmanager_address,
            TOKEN_ADDRESS,
            deposit,
            DEFAULT_SETTLE_TIMEOUT,
        )


if __name__ == '__main__':
    main()
