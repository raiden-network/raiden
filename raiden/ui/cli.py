# -*- coding: utf-8 -*-
from __future__ import print_function

import sys

import signal
import click
import gevent
import gevent.monkey
from ethereum import slogging
from ethereum.utils import decode_hex
from pyethapp.jsonrpc import address_decoder

from raiden.app import App
from raiden.settings import INITIAL_PORT
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import BlockChainService
from raiden.ui.console import Console
from raiden.utils import split_endpoint
from raiden.accounts import AccountManager

gevent.monkey.patch_all()


OPTIONS = [
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
        '--eth-rpc-endpoint',
        help='"host:port" address of ethereum JSON-RPC server.\n'
        'Also accepts a protocol prefix (http:// or https://) with optional port',
        default='127.0.0.1:8545',  # geth default jsonrpc port
        type=str,
    ),
    click.option(
        '--registry-contract-address',
        help='hex encoded address of the registry contract.',
        default='32c5dab9b099a5b6c0e626c1862c07b30f58d76a',  # testnet default
        type=str,
    ),
    click.option(
        '--discovery-contract-address',
        help='hex encoded address of the discovery contract.',
        default='79ab17cc105e820368e695dfa547604651d02cbb',  # testnet default
        type=str,
    ),
    click.option(
        '--listen-address',
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
    click.option(
        '--max-unresponsive-time',
        help=(
            'Max time in seconds for which an address can send no packets and '
            'still be considered healthy. Give 0 in order to disable healthcheck.'
        ),
        default=120,
        type=int,
    ),
    click.option(
        '--send-ping-time',
        help=(
            'Time in seconds after which if we have received no message from a '
            'node we have a connection with, we are going to send a PING message'
        ),
        default=60,
        type=int,
    ),
]


def options(func):
    """Having the common app options as a decorator facilitates reuse.
    """
    for option in OPTIONS:
        func = option(func)
    return func


@options
@click.command()
def app(address,  # pylint: disable=too-many-arguments,too-many-locals
        keystore_path,
        eth_rpc_endpoint,
        registry_contract_address,
        discovery_contract_address,
        listen_address,
        logging,
        logfile,
        max_unresponsive_time,
        send_ping_time):

    slogging.configure(logging, log_file=logfile)

    # config_file = args.config_file
    (listen_host, listen_port) = split_endpoint(listen_address)

    config = App.default_config.copy()
    config['host'] = listen_host
    config['port'] = listen_port
    config['max_unresponsive_time'] = max_unresponsive_time
    config['send_ping_time'] = send_ping_time

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

        print('The following accounts were found in your machine:')
        print('')
        print('\n'.join(formatted_addresses))
        print('')

        while should_prompt:
            idx = click.prompt('Select one of them by index to continue', type=int)

            if idx >= 0 and idx < len(addresses):
                should_prompt = False
            else:
                print("\nError: Provided index '{}' is out of bounds\n".format(idx))

        address = addresses[idx]

    try:
        privatekey_bin = accmgr.get_privkey(address)
    except ValueError as e:
        # ValueError exception raised if the password is incorrect, print the
        # exception message and exit the process, the user may try again by
        # re-executing Raiden.
        print(e.message)
        sys.exit(1)

    privatekey_hex = privatekey_bin.encode('hex')
    config['privatekey_hex'] = privatekey_hex

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

    # user may have provided registry and discovery contracts with leading 0x
    registry_contract_address = address_decoder(registry_contract_address)
    discovery_contract_address = address_decoder(discovery_contract_address)

    try:
        blockchain_service = BlockChainService(
            privatekey_bin,
            registry_contract_address,
            host=rpc_host,
            port=rpc_port,
        )
    except ValueError as e:
        # ValueError exception raised if:
        # - The registry contract address doesn't have code, this might happen
        # if the connected geth process is not synced or if the wrong address
        # is provided (e.g. using the address from a smart contract deployed on
        # ropsten with a geth node connected to morden)
        print(e.message)
        sys.exit(1)

    discovery = ContractDiscovery(
        blockchain_service.node_address,
        blockchain_service.discovery(discovery_contract_address)
    )

    return App(config, blockchain_service, discovery)


@click.option(  # FIXME: implement NAT-punching
    '--external-listen-address',
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
