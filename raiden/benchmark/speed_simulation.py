# -*- coding: utf8 -*-
from __future__ import print_function

import codecs
import random
import signal
import sys

import yaml
import gevent
import networkx

from raiden.app import App
from raiden.network.discovery import Discovery
from raiden.network.rpc.client import BlockChainService
from raiden.utils import privtoaddr, sha3
from raiden.tests.utils import DEFAULT_DEPOSIT


ASSET_ADDRESS = sha3('tps')[:20]


def hostport_to_privkeyaddr(host, port):
    myip_port = '{}:{}'.format(host, port)
    privkey = sha3(myip_port)
    addr = privtoaddr(privkey)

    return privkey, addr


def random_channel_graph(asset_address, blockchain_service, node_addresses, deposit):
    """ Make the raiden network a connected graph by randomly choosing nodes to connect. """
    graph = networkx.Graph()
    graph.add_nodes_from(node_addresses)

    for edge in blockchain_service.addresses_by_asset(asset_address):
        graph.add_edge(edge[0], edge[1])

    while not networkx.is_connected(graph):
        from_address = random.choice(node_addresses)
        to_address = random.choice(node_addresses)

        netcontract_address = blockchain_service.new_netting_contract(
            asset_address,
            from_address,
            to_address,
        )

        blockchain_service.deposit(
            asset_address,
            netcontract_address,
            from_address,
            deposit,
        )

        blockchain_service.deposit(
            asset_address,
            netcontract_address,
            to_address,
            deposit,
        )

        graph.add_edge(from_address, to_address)


def setup_tps(rpc_connection, config_path, registry_address, asset_address, deposit):
    # TODO:
    #  - create/register the channel manager

    blockchain_service = BlockChainService(rpc_connection, registry_address)
    blockchain_service.new_channel_manager_contract(asset_address=asset_address)

    with codecs.open(config_path, encoding='utf8') as handler:
        config = yaml.load(handler)

    node_addresses = []
    for node in config['nodes']:
        privkey = sha3('{}:{}'.format(node['host'], node['port']))
        node_addresses.append(privtoaddr(privkey))

    random_channel_graph(asset_address, blockchain_service, node_addresses, deposit)


def tps_run(host, port, config, rpc_server, channelmanager_address):  # pylint: disable=too-many-locals
    ourprivkey, ouraddress = hostport_to_privkeyaddr(host, port)

    rpc_connection = rpc_server.split(':')
    rpc_connection = (rpc_connection[0], int(rpc_connection[1]))

    with codecs.open(config, encoding='utf8') as handler:
        config = yaml.load(handler)

    config['host'] = host
    config['port'] = port
    config['privkey'] = ourprivkey

    blockchain_server = BlockChainService(rpc_connection, channelmanager_address)

    discovery = Discovery()
    find_ouraddress = False
    for node in config['nodes']:
        nodeid, _ = channelmanager_address(host, port)
        discovery.register(nodeid, node['host'], node['port'])

        if nodeid == ouraddress:
            find_ouraddress = True

    if not find_ouraddress:
        print('We are not registered in the configuration file')
        sys.exit(1)

    app = App(config, blockchain_server, discovery)

    for asset_address in blockchain_server.asset_addresses:
        app.raiden.setup_asset(asset_address, app.config['min_locktime'])

    # wait for interrupt
    event = gevent.event.Event()
    gevent.signal(signal.SIGQUIT, event.set)
    gevent.signal(signal.SIGTERM, event.set)
    gevent.signal(signal.SIGINT, event.set)
    event.wait()

    app.stop()


def main():
    import argparse

    parser = argparse.ArgumentParser()

    kind_parser = parser.add_subparsers(dest='kind')
    runparser = kind_parser.add_parser('run')
    setupparser = kind_parser.add_parser('setup', )

    setupparser.add_argument('rpc_server')
    setupparser.add_argument('config')
    setupparser.add_argument('registry_address')

    runparser.add_argument('rpc_server')
    runparser.add_argument('config')
    runparser.add_argument('host')
    runparser.add_argument('port')

    args = parser.parse_args()

    if args.kind == 'run':
        host = args.host
        port = args.port
    elif args.kind == 'setup':
        args.rpc_server
        args.config
        args.registry_address
        ASSET_ADDRESS
        DEFAULT_DEPOSIT


if __name__ == '__main__':
    main()
