# -*- coding: utf8 -*-
from __future__ import print_function

import signal
import gevent
import click
from ethereum import slogging
from pyethapp.rpc_client import JSONRPCClient

from raiden.raiden_service import RaidenService
from raiden.network.discovery import Discovery
from raiden.network.transport import UDPTransport
from raiden.network.rpc.client import BlockChainService
from raiden.console import Console
from raiden.utils import pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


INITIAL_PORT = 40001
DEFAULT_SETTLE_TIMEOUT = 50
DEFAULT_REVEAL_TIMEOUT = 3


def split_endpoint(endpoint):
    host, port = endpoint.split(':')
    port = int(port)
    return (host, port)


class App(object):  # pylint: disable=too-few-public-methods
    default_config = dict(
        host='',
        port=INITIAL_PORT,
        privkey='',
        # number of blocks that a node requires to learn the secret before the lock expires
        reveal_timeout=DEFAULT_REVEAL_TIMEOUT,
        settle_timeout=DEFAULT_SETTLE_TIMEOUT,
        # how long to wait for a transfer until TimeoutTransfer is sent (time in milliseconds)
        msg_timeout=100.00,
    )

    def __init__(self, config, chain, discovery, transport_class=UDPTransport):
        self.config = config
        self.discovery = discovery
        self.transport = transport_class(config['host'], config['port'])
        self.raiden = RaidenService(chain, config['privkey'], self.transport, discovery, config)
        self.services = {'raiden': self.raiden}
        self.start_console = True

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
        )

    def stop(self):
        self.transport.stop()
        self.raiden.stop()


@click.option('--privkey', help='asks for the hex encoded ethereum private key.'
        'WARNING: do not give the privatekey on the commandline, instead wait for the prompt!',
        type=str,
        prompt=True, hide_input=True)
@click.option('--eth_rpc_endpoint', help='"host:port" address of ethereum JSON-RPC server.',
        default='127.0.0.1:8101',
        type=str
        )
@click.option('--registry_contract_address', help='hex encoded address of the registry contract.',
        default='',
        type=str
        )
@click.option('--discovery_contract_address', help='hex encoded address of the discovery contract.',
        default='',
        type=str,
        )
@click.option('--listen_address', help='"host:port" for the raiden service to listen on.',
        default="0.0.0.0:{}".format(INITIAL_PORT),
        type=str
        )
@click.option('--external_listen_address', help='external "host:port" where the raiden service'
        ' can be contacted on (through NAT).',
        default="",
        type=str
        )  # FIXME: implement NAT-punching
@click.command()
def app(privkey, eth_rpc_endpoint, registry_contract_address, discovery_contract_address,
         listen_address, external_listen_address):

    if not external_listen_address:
        # notify('if you are behind a NAT, you should set
        # `external_listen_address` and configure port forwarding on your router')
        external_listen_address = listen_address

    # config_file = args.config_file
    rpc_connection = split_endpoint(eth_rpc_endpoint)
    (listen_host, listen_port) = split_endpoint(listen_address)

    config = App.default_config.copy()
    config['host'] = listen_host
    config['port'] = listen_port
    config['privkey'] = privkey

    jsonrpc_client = JSONRPCClient(privkey=privkey, host=rpc_connection[0], port=rpc_connection[1], print_communication=False)

    blockchain_service = BlockChainService(
        jsonrpc_client,
        registry_contract_address.decode('hex'),
    )
    discovery = Discovery()

    app = App(config, blockchain_service, discovery)

    discovery.register(app.raiden.address, *split_endpoint(external_listen_address))

    for asset_address in blockchain_service.default_registry.asset_addresses():
        manager = blockchain_service.manager_by_asset(asset_address)
        app.raiden.register_channel_manager(manager)

    # TODO:
    # - Ask for confirmation to quit if there are any locked transfers that did
    # not timeout.

    console = Console(app)
    console.start()

    # wait for interrupt
    event = gevent.event.Event()
    gevent.signal(signal.SIGQUIT, event.set)
    gevent.signal(signal.SIGTERM, event.set)
    gevent.signal(signal.SIGINT, event.set)
    event.wait()

    app.stop()


if __name__ == '__main__':
    app()
