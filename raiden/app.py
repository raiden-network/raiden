# -*- coding: utf-8 -*-
from __future__ import print_function

import signal
import gevent
import click
import gevent.monkey
from ethereum import slogging
from ethereum.utils import encode_hex, decode_hex

from raiden.raiden_service import RaidenService, DEFAULT_REVEAL_TIMEOUT, DEFAULT_SETTLE_TIMEOUT
from raiden.network.discovery import ContractDiscovery
from raiden.network.transport import UDPTransport
from raiden.network.rpc.client import BlockChainService
from raiden.console import Console
from raiden.utils import pex, split_endpoint
from raiden.accounts import AccountManager

gevent.monkey.patch_all()

INITIAL_PORT = 40001
DEFAULT_EVENTS_POLL_TIMEOUT = 0.5


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
            decode_hex(config['privatekey_hex']),
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

_options = [
    click.option(
        '--address',
        help=('The ethereum address you would like raiden to use and for which '
              'a keystore file exists in your local system.'),
        default=None,
        type=str,
    ),
    click.option(
        '--keystore-path',
        help=('If you have a non-standard path for the ethereum keystore directory'
              ' provide it using this argument.'),
        default=None,
        type=click.Path(exists=True),
    ),
    click.option(
        '--eth_rpc_endpoint',
        help='"host:port" address of ethereum JSON-RPC server.\n'
        'Also accepts a protocol prefix (http:// or https://) with optional port',
        default='127.0.0.1:8545',  # geth default jsonrpc port
        type=str,
    ),
    click.option(
        '--registry_contract_address',
        help='hex encoded address of the registry contract.',
        default='07d153249abe665be6ca49999952c7023abb5169',  # testnet default
        type=str,
    ),
    click.option(
        '--discovery_contract_address',
        help='hex encoded address of the discovery contract.',
        default='1376c0c3e876ed042df42320d8a554a51c8c8a87',  # testnet default
        type=str,
    ),
    click.option(
        '--listen_address',
        help='"host:port" for the raiden service to listen on.',
        default="0.0.0.0:{}".format(INITIAL_PORT),
        type=str,
    ),
    click.option(
        '--logging',
        help='ethereum.slogging config-string (\'<logger1>:<level>,<logger2>:<level>\')',
        default=':INFO',
        type=str,
    ),
    click.option(
        '--logfile',
        help='file path for logging to file',
        default=None,
        type=str,
    ),
]


def options(func):
    """Having the common app options as a decorator facilitates reuse.
    """
    for option in _options:
        func = option(func)
    return func


@options
@click.command()
def app(address,
        keystore_path,
        eth_rpc_endpoint,
        registry_contract_address,
        discovery_contract_address,
        listen_address,
        logging,
        logfile):

    slogging.configure(logging, log_file=logfile)

    # config_file = args.config_file
    (listen_host, listen_port) = split_endpoint(listen_address)

    config = App.default_config.copy()
    config['host'] = listen_host
    config['port'] = listen_port

    accmgr = AccountManager(keystore_path)
    if not accmgr.accounts:
        raise RuntimeError('No Ethereum accounts found in the user\'s system')

    if not accmgr.address_in_keystore(address):
        addresses = list(accmgr.accounts.keys())
        formatted_addresses = [
            '[{:3d}] - 0x{}'.format(idx, addr)
            for idx, addr in enumerate(addresses)
        ]

        should_prompt = True
        while should_prompt:
            idx = click.prompt(
                "The following accounts were found in your machine:\n\n{}"
                "\nSelect one of them by index to continue: ".format(
                    "\n".join(formatted_addresses)),
                type=int
            )
            if idx >= 0 and idx < len(addresses):
                should_prompt = False
            else:
                print("\nError: Provided index '{}' is out of bounds\n".format(idx))

        address = addresses[idx]

    privatekey = accmgr.get_privkey(address)
    config['privatekey_hex'] = encode_hex(privatekey)

    endpoint = eth_rpc_endpoint

    if eth_rpc_endpoint.startswith("http://"):
        endpoint = eth_rpc_endpoint[len("http://"):]
        rpc_port = 80
    elif eth_rpc_endpoint.startswith("https://"):
        endpoint = eth_rpc_endpoint[len("https://"):]
        rpc_port = 443

    if ':' not in endpoint:  # no port was given in url
        rpc_host = endpoint
    else:
        rpc_host, rpc_port = split_endpoint(endpoint)

    blockchain_service = BlockChainService(
        privatekey,
        decode_hex(registry_contract_address),
        host=rpc_host,
        port=rpc_port,
    )

    discovery = ContractDiscovery(
        blockchain_service,
        decode_hex(discovery_contract_address)  # FIXME: double encoding
    )

    return App(config, blockchain_service, discovery)


@click.option(  # FIXME: implement NAT-punching
    '--external_listen_address',
    help='external "host:port" where the raiden service can be contacted on (through NAT).',
    default='',
    type=str,
)
@options
@click.command()
@click.pass_context
def run(ctx, external_listen_address, **kwargs):
    # TODO:
    # - Ask for confirmation to quit if there are any locked transfers that did
    # not timeout.

    if not external_listen_address:
        # notify('if you are behind a NAT, you should set
        # `external_listen_address` and configure port forwarding on your router')
        external_listen_address = kwargs['listen_address']

    ctx.params.pop('external_listen_address')
    app_ = ctx.invoke(app, **kwargs)

    app_.discovery.register(
        app_.raiden.address,
        *split_endpoint(external_listen_address)
    )

    app_.raiden.register_registry(app_.raiden.chain.default_registry)

    console = Console(app_)
    console.start()

    # wait for interrupt
    event = gevent.event.Event()
    gevent.signal(signal.SIGQUIT, event.set)
    gevent.signal(signal.SIGTERM, event.set)
    gevent.signal(signal.SIGINT, event.set)
    event.wait()

    app.stop()


if __name__ == '__main__':
    run()
