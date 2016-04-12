# -*- coding: utf8 -*-
from __future__ import print_function

import codecs
import sys
import signal

import yaml
import gevent
from ethereum import slogging

from raiden.raiden_service import RaidenService
from raiden.network.discovery import Discovery
from raiden.network.transport import UDPTransport
from raiden.network.rpc.client import BlockChainService

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


INITIAL_PORT = 40001


class App(object):  # pylint: disable=too-few-public-methods
    default_config = dict(
        host='',
        port=INITIAL_PORT,
        privkey='',
        min_locktime=10,
    )

    def __init__(self, config, chain, discovery, transport_class=UDPTransport):
        self.config = config
        self.transport = transport_class(config['host'], config['port'])
        self.raiden = RaidenService(chain, config['privkey'], self.transport, discovery)
        discovery.register(self.raiden.address, self.transport.host, self.transport.port)
        self.discovery = discovery

    def stop(self):
        self.transport.server.start()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('rpc_server', help='The host:port of the json-rpc server')
    parser.add_argument('registry_address', help='The asset registry contract address')
    parser.add_argument('config_file', help='Configuration file for the raiden note')

    parser.add_argument(
        '-h',
        '--host',
        default='0.0.0.0',
        help='Local address that the raiden app will bind to',
    )
    parser.add_argument(
        '-p',
        '--port',
        default=INITIAL_PORT,
        help='Local port that the raiden app will bind to',
    )

    args = parser.parse_args()

    rpc_connection = args.rpc_server.split(':')
    rpc_connection = (rpc_connection[0], int(rpc_connection[1]))
    config_file = args.config_file
    host = args.host
    port = args.port

    with codecs.open(config_file, encoding='utf8') as handler:
        config = yaml.load(handler)

    config['host'] = host
    config['port'] = port

    if 'privkey' not in config:
        print('Missing "privkey" in the configuration file, cannot proceed')
        sys.exit(1)

    blockchain_server = BlockChainService(rpc_connection, args.registry_address)
    discovery = Discovery()

    for node in config['nodes']:
        discovery.register(node['nodeid'], node['host'], node['port'])

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


if __name__ == '__main__':
    main()
