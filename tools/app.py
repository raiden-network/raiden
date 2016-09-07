# -*- coding: utf8 -*-
from __future__ import print_function

from gevent import monkey
monkey.patch_all()

import signal
import gevent
import click
import json
from ethereum import slogging
from pyethapp.rpc_client import JSONRPCClient

from raiden.raiden_service import RaidenService, DEFAULT_REVEAL_TIMEOUT, DEFAULT_SETTLE_TIMEOUT
from raiden.network.discovery import ContractDiscovery
from raiden.network.transport import UDPTransport
from raiden.network.rpc.client import BlockChainService
from raiden.utils import pex, split_endpoint
from raiden.console import ConsoleTools

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


INITIAL_PORT = 40001


class App(object):  # pylint: disable=too-few-public-methods
    default_config = dict(
        host='',
        port=INITIAL_PORT,
        privatekey_hex='',
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
        self.raiden = RaidenService(
            chain,
            config['privatekey_hex'].decode('hex'),
            self.transport,
            discovery,
            config,
        )
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


@click.option(
    '--privatekey_file',
    help='Read private key from file.\n',
    type=str,
)
@click.option(
    '--eth_rpc_endpoint',
    help='"host:port" address of ethereum JSON-RPC server.\n'
    'Also accepts a protocol prefix (http:// or https://) with optional port',
    default='127.0.0.1:8545',  # geth default jsonrpc port
    type=str,
)
@click.option(
    '--registry_contract_address',
    help='hex encoded address of the registry contract.',
    default='07d153249abe665be6ca49999952c7023abb5169',  # testnet default
    type=str,
)
@click.option(
    '--discovery_contract_address',
    help='hex encoded address of the discovery contract.',
    default='1376c0c3e876ed042df42320d8a554a51c8c8a87',  # testnet default
    type=str,
)
@click.option(
    '--listen_address',
    help='"host:port" for the raiden service to listen on.',
    default="0.0.0.0:{}".format(INITIAL_PORT),
    type=str,
)
@click.option(  # FIXME: implement NAT-punching
    '--external_listen_address',
    help='external "host:port" where the raiden service can be contacted on (through NAT).',
    default='',
    type=str,
    )
@click.option(
    '--logging',
    help='ethereum.slogging config-string (\'<logger1>:<level>,<logger2>:<level>\')',
    default=':INFO',
    type=str,
    )
@click.option(
    '--scenario',
    help='receive a json file with a list of channels to open and transfers to do.',
    default='',
    type=str,
    )
@click.option(
    '--logfile',
    help='file path for logging to file',
    default=None,
    type=str,
    )
@click.command()
def app(privatekey_file, eth_rpc_endpoint, registry_contract_address,
        discovery_contract_address, listen_address, external_listen_address,
        logging, scenario, logfile):

    slogging.configure(logging, log_file=logfile)

    if not external_listen_address:
        # notify('if you are behind a NAT, you should set
        # `external_listen_address` and configure port forwarding on your router')
        external_listen_address = listen_address

    # config_file = args.config_file
    (listen_host, listen_port) = split_endpoint(listen_address)

    config = App.default_config.copy()
    config['host'] = listen_host
    config['port'] = listen_port

    with open(privatekey_file) as f:
        privatekey = f.read().rstrip()
    config['privatekey_hex'] = privatekey

    endpoint = eth_rpc_endpoint
    use_ssl = False

    if eth_rpc_endpoint.startswith("http://"):
        endpoint = eth_rpc_endpoint[len("http://"):]
        rpc_port = 80
    elif eth_rpc_endpoint.startswith("https://"):
        endpoint = eth_rpc_endpoint[len("https://"):]
        use_ssl = True
        rpc_port = 443

    if not ':' in endpoint:  # no port was given in url
        rpc_host = endpoint
    else:
        rpc_host, rpc_port = split_endpoint(endpoint)

    jsonrpc_client = JSONRPCClient(
        privkey=privatekey,
        host=rpc_host,
        port=rpc_port,
        print_communication=False,
        use_ssl=use_ssl,
    )

    blockchain_service = BlockChainService(
        jsonrpc_client,
        registry_contract_address.decode('hex'),
    )
    discovery = ContractDiscovery(jsonrpc_client, discovery_contract_address.decode('hex'))  # FIXME: double encoding

    app = App(config, blockchain_service, discovery)

    discovery.register(app.raiden.address, *split_endpoint(external_listen_address))

    app.raiden.register_registry(blockchain_service.default_registry)

    if scenario:
        with open(scenario) as f:
            script = json.load(f)

        tools = ConsoleTools(
                app.raiden,
                discovery,
                app.config['settle_timeout'],
                app.config['reveal_timeout'],
        )

        transfers_by_channel = {}

        tokens = script['assets']
        for token in tokens:
            # skip tokens/assets that we're not part of
            if not app.raiden.address.encode('hex') in token['channels']:
                continue

            # allow for prefunded tokens
            if 'token_address' in token:
                token_address = token['token_address']
            else:
                token_address = tools.create_token()

            transfers_with_amount = token['transfers_with_amount']
            for node in token['channels']:
                # FIXME: in order to do bidirectional channels, only one side
                # (i.e. only token['channels'][0]) should
                # open; others should join by calling
                # raiden.api.deposit, AFTER the channel came alive!
                if node != app.raiden.address.encode('hex'):
                    tools.register_asset(token_address)
                    channel = tools.open_channel_with_funding(
                        token_address, node, 1000)
                    transfers_by_channel[channel] = int(transfers_with_amount[node])

        def transfer(token_address, amount_per_transfer, total_transfers, channel):
            peer = channel.partner(app.raiden.address)

            def transfer_():
                for _ in xrange(total_transfers):
                    app.raiden.transfer(token_address, amount_per_transfer, peer)

            return gevent.spawn(
                transfer, amount_per_transfer, peer
            )

        greenlets = []
        for channel, amount in transfers_by_channel.items():
            greenlets.append(transfer(token_address, 1, amount, channel))

        gevent.joinall(greenlets)

    else:
        # wait for interrupt
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

    app.stop()


if __name__ == '__main__':
    app()
