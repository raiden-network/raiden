# -*- coding: utf-8 -*-
from __future__ import print_function

import sys
import os
import tempfile
import json

import signal
import click
import gevent
import gevent.monkey
from ethereum import slogging
from pyethapp.jsonrpc import address_decoder, address_encoder
from tinyrpc import BadRequestError
from ethereum.utils import denoms

from raiden.accounts import AccountManager
from raiden.api.rest import APIServer, RestAPI
from raiden.constants import (
    ROPSTEN_REGISTRY_ADDRESS,
    ROPSTEN_DISCOVERY_ADDRESS,
    DISCOVERY_REGISTRATION_GAS
)
from raiden.network.discovery import ContractDiscovery
from raiden.network.sockfactory import socket_factory
from raiden.settings import (
    INITIAL_PORT,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    GAS_PRICE
)
from raiden.utils import split_endpoint
from raiden.tests.utils.smoketest import (
    load_or_create_smoketest_config,
    start_ethereum,
    run_smoketests,
)

gevent.monkey.patch_all()


class AddressType(click.ParamType):
    name = 'address'

    def convert(self, value, param, ctx):
        try:
            return address_decoder(value)
        except BadRequestError:
            self.fail('Please specify a valid hex-encoded address.')


ADDRESS_TYPE = AddressType()

OPTIONS = [
    click.option(
        '--address',
        help=('The ethereum address you would like raiden to use and for which '
              'a keystore file exists in your local system.'),
        default=None,
        type=ADDRESS_TYPE,
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
        default=ROPSTEN_REGISTRY_ADDRESS,  # testnet default
        type=ADDRESS_TYPE,
    ),
    click.option(
        '--discovery-contract-address',
        help='hex encoded address of the discovery contract.',
        default=ROPSTEN_DISCOVERY_ADDRESS,  # testnet default
        type=ADDRESS_TYPE,
    ),
    click.option(
        '--listen-address',
        help='"host:port" for the raiden service to listen on.',
        default="0.0.0.0:{}".format(INITIAL_PORT),
        type=str,
    ),
    click.option(
        '--rpccorsdomain',
        help='Comma separated list of domains to accept cross origin requests. \n'
        '(localhost enabled by default)',
        default="http://localhost:*/*",
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
            'still be considered healthy.'
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
    click.option(
        '--console/--no-console',
        help=(
            'Start with or without the command line interface. Default is to '
            'start with the CLI disabled'
        ),
        default=False,
    ),
    click.option(
        '--rpc/--no-rpc',
        help=(
            'Start with or without the RPC server. Default is to start '
            'the RPC server'
        ),
        default=True,
    ),
    click.option(
        '--api-address',
        help='"host:port" for the RPC server to listen on.',
        default="127.0.0.1:5001",
        type=str,
    ),
    click.option(
        '--datadir',
        help='Directory for storing raiden data.',
        default=None,
        type=click.Path(
            exists=False,
            dir_okay=True,
            file_okay=False,
            writable=True,
            resolve_path=True,
            allow_dash=False,
        ),
    ),
    click.option(
        '--password-file',
        help='Text file containing password for provided account',
        default=None,
        type=click.File(lazy=True),
    ),
    click.option(
        '--web-ui/--no-web-ui',
        help=(
            'Start with or without the web interface. Requires --rpc. '
            'It will be acessible at http://<api-address>. '
            'Default is to start with the web UI enabled'
        ),
        default=True,
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
def app(address,
        keystore_path,
        eth_rpc_endpoint,
        registry_contract_address,
        discovery_contract_address,
        listen_address,
        rpccorsdomain,  # pylint: disable=unused-argument
        mapped_socket,
        logging,
        logfile,
        max_unresponsive_time,
        send_ping_time,
        api_address,
        rpc,
        console,
        password_file,
        web_ui,
        datadir):

    from raiden.app import App
    from raiden.network.rpc.client import BlockChainService

    # config_file = args.config_file
    (listen_host, listen_port) = split_endpoint(listen_address)
    (api_host, api_port) = split_endpoint(api_address)

    config = App.DEFAULT_CONFIG.copy()
    config['host'] = listen_host
    config['port'] = listen_port
    config['console'] = console
    config['rpc'] = rpc
    config['web_ui'] = rpc and web_ui
    config['api_host'] = api_host
    config['api_port'] = api_port

    if mapped_socket:
        config['socket'] = mapped_socket.socket
        config['external_ip'] = mapped_socket.external_ip
        config['external_port'] = mapped_socket.external_port
    else:
        config['socket'] = None
        config['external_ip'] = listen_host
        config['external_port'] = listen_port

    retries = max_unresponsive_time / DEFAULT_NAT_KEEPALIVE_RETRIES
    config['protocol']['nat_keepalive_retries'] = retries
    config['protocol']['nat_keepalive_timeout'] = send_ping_time

    address_hex = address_encoder(address) if address else None
    address_hex, privatekey_bin = prompt_account(address_hex, keystore_path, password_file)

    privatekey_hex = privatekey_bin.encode('hex')
    config['privatekey_hex'] = privatekey_hex

    endpoint = eth_rpc_endpoint

    # Fallback default port if only an IP address is given
    rpc_port = 8545
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

    discovery_tx_cost = GAS_PRICE * DISCOVERY_REGISTRATION_GAS
    while True:
        balance = blockchain_service.client.balance(address_hex)
        if discovery_tx_cost <= balance:
            break
        print(
            'Account has insufficient funds for discovery registration.\n'
            'Needed: {} ETH\n'
            'Available: {} ETH.\n'
            'Please deposit additional funds on this account.'
            .format(discovery_tx_cost / float(denoms.ether), balance / float(denoms.ether))
        )
        if not click.confirm('Try again?'):
            sys.exit(1)

    discovery = ContractDiscovery(
        blockchain_service.node_address,
        blockchain_service.discovery(discovery_contract_address)
    )

    if datadir is None:
        # default database directory
        raiden_directory = os.path.join(os.path.expanduser('~'), '.raiden')
    else:
        raiden_directory = datadir

    if not os.path.exists(raiden_directory):
        os.makedirs(raiden_directory)
    user_db_dir = os.path.join(raiden_directory, address_hex[:8])
    if not os.path.exists(user_db_dir):
        os.makedirs(user_db_dir)
    database_path = os.path.join(user_db_dir, 'log.db')
    config['database_path'] = database_path

    return App(config, blockchain_service, discovery)


def prompt_account(address_hex, keystore_path, password_file):
    accmgr = AccountManager(keystore_path)
    if not accmgr.accounts:
        raise RuntimeError('No Ethereum accounts found in the user\'s system')

    if not accmgr.address_in_keystore(address_hex):
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

        address_hex = addresses[idx]

    password = None
    if password_file:
        password = password_file.read().splitlines()[0]
    if password:
        try:
            privatekey_bin = accmgr.get_privkey(address_hex, password)
        except ValueError:
            # ValueError exception raised if the password is incorrect
            print('Incorrect password for {} in file. Aborting ...'.format(address))
            sys.exit(1)
    else:
        unlock_tries = 3
        while True:
            try:
                privatekey_bin = accmgr.get_privkey(address_hex)
                break
            except ValueError:
                # ValueError exception raised if the password is incorrect
                if unlock_tries == 0:
                    print(
                        'Exhausted passphrase unlock attempts for {}. Aborting ...'
                        .format(address_hex)
                    )
                    sys.exit(1)

                print(
                    'Incorrect passphrase to unlock the private key. {} tries remaining. '
                    'Please try again or kill the process to quit. '
                    'Usually Ctrl-c.'.format(unlock_tries)
                )
                unlock_tries -= 1

    return address_hex, privatekey_bin


@click.group(invoke_without_command=True)
@options
@click.pass_context
def run(ctx, **kwargs):
    if ctx.invoked_subcommand is None:
        from raiden.api.python import RaidenAPI
        from raiden.ui.console import Console

        slogging.configure(kwargs['logging'], log_file=kwargs['logfile'])

        # TODO:
        # - Ask for confirmation to quit if there are any locked transfers that did
        # not timeout.
        (listen_host, listen_port) = split_endpoint(kwargs['listen_address'])
        with socket_factory(listen_host, listen_port) as mapped_socket:
            kwargs['mapped_socket'] = mapped_socket

            app_ = ctx.invoke(app, **kwargs)

            domain_list = []
            if kwargs['rpccorsdomain']:
                if ',' in kwargs['rpccorsdomain']:
                    for domain in kwargs['rpccorsdomain'].split(','):
                        domain_list.append(str(domain))
                else:
                    domain_list.append(str(kwargs['rpccorsdomain']))

            if ctx.params['rpc']:
                raiden_api = RaidenAPI(app_.raiden)
                rest_api = RestAPI(raiden_api)
                api_server = APIServer(
                    rest_api,
                    cors_domain_list=domain_list,
                    web_ui=ctx.params['web_ui'],
                )
                (api_host, api_port) = split_endpoint(kwargs["api_address"])
                api_server.start(api_host, api_port)

                print(
                    "The Raiden API RPC server is now running at http://{}:{}/.\n\n"
                    "See the Raiden documentation for all available endpoints at\n"
                    "https://github.com/raiden-network/raiden/blob/master"
                    "/docs/Rest-Api.rst".format(
                        api_host,
                        api_port,
                    )
                )

            if ctx.params['console']:
                console = Console(app_)
                console.start()

            # wait for interrupt
            event = gevent.event.Event()
            gevent.signal(signal.SIGQUIT, event.set)
            gevent.signal(signal.SIGTERM, event.set)
            gevent.signal(signal.SIGINT, event.set)
            event.wait()

            try:
                api_server.stop()
            except NameError:
                pass
        app_.stop(leave_channels=False)


@run.command()
@click.option(
    '--debug/--no-debug',
    default=False,
    help='Drop into pdb on errors (default: False).'
)
@click.pass_context
def smoketest(ctx, debug, **kwargs):
    """ Test, that the raiden installation is sane.
    """
    report_file = tempfile.mktemp(suffix=".log")
    open(report_file, 'w+')

    def append_report(subject, data):
        with open(report_file, 'a') as handler:
            handler.write('{:=^80}'.format(' %s ' % subject.upper()) + os.linesep)
            if data is not None:
                handler.writelines([(data + os.linesep).encode('utf-8')])

    append_report('raiden log', None)

    print("[1/5] getting smoketest configuration")
    smoketest_config = load_or_create_smoketest_config()

    print("[2/5] starting ethereum")
    ethereum, ethereum_config = start_ethereum(smoketest_config['genesis'])

    print('[3/5] starting raiden')

    # setup logging to log only into our report file
    slogging.configure(':DEBUG', log_file=report_file)
    root = slogging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, slogging.logging.StreamHandler):
            root.handlers.remove(handler)
            break
    # setup cli arguments for starting raiden
    args = dict(
        discovery_contract_address=smoketest_config['contracts']['discovery_address'],
        registry_contract_address=smoketest_config['contracts']['registry_address'],
        eth_rpc_endpoint='http://127.0.0.1:{}'.format(ethereum_config['rpc']),
        keystore_path=ethereum_config['keystore'],
        address=ethereum_config['address'],
    )
    for option in app.params:
        if option.name in args.keys():
            args[option.name] = option.process_value(ctx, args[option.name])
        else:
            args[option.name] = option.default

    password_file = os.path.join(args['keystore_path'], 'password')
    with open(password_file, 'w') as handler:
        handler.write('password')

    args['mapped_socket'] = None
    args['password_file'] = click.File()(password_file)
    args['datadir'] = args['keystore_path']

    # invoke the raiden app
    app_ = ctx.invoke(app, **args)

    success = False
    try:
        print('[4/5] running smoketests...')
        error = run_smoketests(app_.raiden, smoketest_config, debug=debug)
        if error is not None:
            append_report('smoketest assertion error', error)
        else:
            success = True
    finally:
        app_.stop()
        ethereum.send_signal(2)

        err, out = ethereum.communicate()
        append_report('geth init stdout', ethereum_config['init_log_out'].decode('utf-8'))
        append_report('geth init stderr', ethereum_config['init_log_err'].decode('utf-8'))
        append_report('ethereum stdout', out)
        append_report('ethereum stderr', err)
        append_report('smoketest configuration', json.dumps(smoketest_config))
    if success:
        print('[5/5] smoketest successful, report was written to {}'.format(report_file))
    else:
        print('[5/5] smoketest had errors, report was written to {}'.format(report_file))
        sys.exit(1)
