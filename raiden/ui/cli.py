# -*- coding: utf-8 -*-
from binascii import hexlify
import sys
import os
import re
import tempfile
import json
import socket
import errno
import signal
from itertools import count
from ipaddress import IPv4Address, AddressValueError

import click
import gevent
import gevent.monkey
import requests
from requests.exceptions import RequestException
from ethereum import slogging
from ethereum.utils import denoms

from raiden.accounts import AccountManager
from raiden.api.rest import APIServer, RestAPI
from raiden.constants import (
    ID_TO_NETWORKNAME,
    ROPSTEN_DISCOVERY_ADDRESS,
    ROPSTEN_REGISTRY_ADDRESS,
)
from raiden.exceptions import EthNodeCommunicationError
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.sockfactory import SocketFactory
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    ETHERSCAN_API,
    INITIAL_PORT,
    ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE,
)
from raiden.utils import (
    address_decoder,
    address_encoder,
    quantity_decoder,
    split_endpoint,
    get_system_spec,
)
from raiden.tests.utils.smoketest import (
    load_or_create_smoketest_config,
    start_ethereum,
    run_smoketests,
)

gevent.monkey.patch_all()

# ansi escape code for moving the cursor and clearing the line
CURSOR_STARTLINE = '\x1b[1000D'
CLEARLINE = '\x1b[2K'

# 52100 gas is how much registerEndpoint() costs. Rounding to 60k for safety.
DISCOVERY_TX_GAS_LIMIT = 60000


def toogle_cpu_profiler(raiden):
    try:
        from raiden.utils.profiling.cpu import CpuProfiler
    except ImportError:
        slogging.get_logger(__name__).exception('cannot start cpu profiler')
        return

    if hasattr(raiden, 'profiler') and isinstance(raiden.profiler, CpuProfiler):
        raiden.profiler.stop()
        raiden.profiler = None

    elif not hasattr(raiden, 'profiler') and raiden.config['database_path'] != ':memory:':
        raiden.profiler = CpuProfiler(raiden.config['database_path'])
        raiden.profiler.start()


def toggle_trace_profiler(raiden):
    try:
        from raiden.utils.profiling.trace import TraceProfiler
    except ImportError:
        slogging.get_logger(__name__).exception('cannot start tracer profiler')
        return

    if hasattr(raiden, 'profiler') and isinstance(raiden.profiler, TraceProfiler):
        raiden.profiler.stop()
        raiden.profiler = None

    elif not hasattr(raiden, 'profiler') and raiden.config['database_path'] != ':memory:':
        raiden.profiler = TraceProfiler(raiden.config['database_path'])
        raiden.profiler.start()


def check_json_rpc(client):
    try:
        client_version = client.call('web3_clientVersion')
    except (requests.exceptions.ConnectionError, EthNodeCommunicationError):
        print(
            "\n"
            "Couldn't contact the ethereum node through JSON-RPC.\n"
            "Please make sure that JSON-RPC is enabled for these interfaces:\n"
            "\n"
            "    eth_*, net_*, web3_*\n"
            "\n"
            "geth: https://github.com/ethereum/go-ethereum/wiki/Management-APIs\n"
        )
        return False
    else:
        if client_version.startswith('Parity'):
            major, minor, patch = [
                int(x) for x in re.search(r'//v(\d+)\.(\d+)\.(\d+)', client_version).groups()
            ]
            if (major, minor, patch) < (1, 7, 6):
                print('You need Byzantium enabled parity. >= 1.7.6 / 1.8.0')
                return False
        elif client_version.startswith('Geth'):
            major, minor, patch = [
                int(x) for x in re.search(r'/v(\d+)\.(\d+)\.(\d+)', client_version).groups()
            ]
            if (major, minor, patch) < (1, 7, 2):
                print('You need Byzantium enabled geth. >= 1.7.2')
                return False
        else:
            print('Unsupported client {} detected.'.format(client_version))
            return False

    return True


def init_minified_addr_checker():
    return re.compile('(0x)?[a-f0-9]{6,8}')


def check_minified_address(addr, compiled_re):
    return compiled_re.match(addr)


def check_synced(blockchain_service):
    try:
        net_id = int(blockchain_service.client.call('net_version'))
        network = ID_TO_NETWORKNAME[net_id]
    except (EthNodeCommunicationError, RequestException):
        print(
            "Couldn't determine the network the ethereum node is connected.\n"
            "Because of this there is no way to determine the latest\n"
            "block with an oracle, and the events from the ethereum\n"
            "node cannot be trusted. Giving up.\n"
        )
        sys.exit(1)
    except KeyError:
        print(
            'Your ethereum client is connected to a non-recognized private \n'
            'network with network-ID {}. Since we can not check if the client \n'
            'is synced please restart raiden with the --no-sync-check argument.'
            '\n'.format(net_id)
        )
        sys.exit(1)

    url = ETHERSCAN_API.format(
        network=network,
        action='eth_blockNumber',
    )
    wait_for_sync(
        blockchain_service,
        url=url,
        tolerance=ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE,
        sleep=3,
    )


def etherscan_query_with_retries(url, sleep, retries=3):
    for _ in range(retries - 1):
        try:
            etherscan_block = quantity_decoder(requests.get(url).json()['result'])
        except (RequestException, ValueError, KeyError):
            gevent.sleep(sleep)
        else:
            return etherscan_block

    etherscan_block = quantity_decoder(requests.get(url).json()['result'])
    return etherscan_block


def wait_for_sync_etherscan(blockchain_service, url, tolerance, sleep):
    local_block = blockchain_service.client.block_number()
    etherscan_block = etherscan_query_with_retries(url, sleep)
    syncing_str = 'Syncing ... Current: {} / Target: ~{}'

    if local_block >= etherscan_block - tolerance:
        return

    print('Waiting for the ethereum node to synchronize. [Use ^C to exit]')
    print(syncing_str.format(local_block, etherscan_block), end='')

    for i in count():
        sys.stdout.flush()
        gevent.sleep(sleep)
        local_block = blockchain_service.client.block_number()

        # update the oracle block number sparsely to not spam the server
        if local_block >= etherscan_block or i % 50 == 0:
            etherscan_block = etherscan_query_with_retries(url, sleep)

            if local_block >= etherscan_block - tolerance:
                return

        print(CLEARLINE + CURSOR_STARTLINE, end='')
        print(syncing_str.format(local_block, etherscan_block), end='')


def wait_for_sync_rpc_api(blockchain_service, sleep):
    if blockchain_service.is_synced():
        return

    print('Waiting for the ethereum node to synchronize [Use ^C to exit].')

    for i in count():
        if i % 3 == 0:
            print(CLEARLINE + CURSOR_STARTLINE, end='')

        print('.', end='')
        sys.stdout.flush()

        gevent.sleep(sleep)

        if blockchain_service.is_synced():
            return


def wait_for_sync(blockchain_service, url, tolerance, sleep):
    # print something since the actual test may take a few moments for the first
    # iteration
    print('Checking if the ethereum node is synchronized')

    try:
        wait_for_sync_etherscan(blockchain_service, url, tolerance, sleep)
    except (RequestException, ValueError, KeyError):
        print('Cannot use {}. Request failed'.format(url))
        print('Falling back to eth_sync api.')

        wait_for_sync_rpc_api(blockchain_service, sleep)


class AddressType(click.ParamType):
    name = 'address'

    def convert(self, value, param, ctx):
        try:
            return address_decoder(value)
        except TypeError:
            self.fail('Please specify a valid hex-encoded address.')


class NATChoiceType(click.Choice):
    def convert(self, value, param, ctx):
        if value.startswith('ext:'):
            ip, _, port = value[4:].partition(':')
            try:
                IPv4Address(ip)
            except AddressValueError:
                self.fail('invalid IP address: {}'.format(ip), param, ctx)
            if port:
                try:
                    port = int(port, 0)
                except ValueError:
                    self.fail('invalid port number: {}'.format(port), param, ctx)
            else:
                port = None
            return ip, port
        return super().convert(value, param, ctx)


ADDRESS_TYPE = AddressType()


OPTIONS = [
    click.option(
        '--address',
        help=('The ethereum address you would like raiden to use and for which '
              'a keystore file exists in your local system.'),
        default=None,
        type=ADDRESS_TYPE,
        show_default=True,
    ),
    click.option(
        '--keystore-path',
        help=('If you have a non-standard path for the ethereum keystore directory'
              ' provide it using this argument.'),
        default=None,
        type=click.Path(exists=True),
        show_default=True,
    ),
    click.option(
        '--gas-price',
        help=(
            'Set the gas price for ethereum transactions. If not provided '
            'the value of the RPC calls eth_gasPrice is going to be used'
        ),
        default=None,
        type=int
    ),
    click.option(
        '--eth-rpc-endpoint',
        help='"host:port" address of ethereum JSON-RPC server.\n'
        'Also accepts a protocol prefix (http:// or https://) with optional port',
        default='127.0.0.1:8545',  # geth default jsonrpc port
        type=str,
        show_default=True,
    ),
    click.option(
        '--registry-contract-address',
        help='hex encoded address of the registry contract.',
        default=ROPSTEN_REGISTRY_ADDRESS,  # testnet default
        type=ADDRESS_TYPE,
        show_default=True,
    ),
    click.option(
        '--discovery-contract-address',
        help='hex encoded address of the discovery contract.',
        default=ROPSTEN_DISCOVERY_ADDRESS,  # testnet default
        type=ADDRESS_TYPE,
        show_default=True,
    ),
    click.option(
        '--listen-address',
        help='"host:port" for the raiden service to listen on.',
        default='0.0.0.0:{}'.format(INITIAL_PORT),
        type=str,
        show_default=True,
    ),
    click.option(
        '--rpccorsdomain',
        help='Comma separated list of domains to accept cross origin requests.',
        default='http://localhost:*/*',
        type=str,
        show_default=True,
    ),
    click.option(
        '--logging',
        help='ethereum.slogging config-string (\'<logger1>:<level>,<logger2>:<level>\')',
        default=':INFO',
        type=str,
        show_default=True,
    ),
    click.option(
        '--logfile',
        help='file path for logging to file',
        default=None,
        type=str,
        show_default=True,
    ),
    click.option(
        '--log-json',
        help='Output log lines in JSON format',
        is_flag=True
    ),
    click.option(
        '--max-unresponsive-time',
        help=(
            'Max time in seconds for which an address can send no packets and '
            'still be considered healthy.'
        ),
        default=30,
        type=int,
        show_default=True,
    ),
    click.option(
        '--send-ping-time',
        help=(
            'Time in seconds after which if we have received no message from a '
            'node we have a connection with, we are going to send a PING message'
        ),
        default=60,
        type=int,
        show_default=True,
    ),
    click.option(
        '--console',
        help='Start the interactive raiden console',
        is_flag=True
    ),
    click.option(
        '--rpc/--no-rpc',
        help='Start with or without the RPC server.',
        default=True,
        show_default=True,
    ),
    click.option(
        '--sync-check/--no-sync-check',
        help='Checks if the ethereum node is synchronized against etherscan.',
        default=True,
        show_default=True,
    ),
    click.option(
        '--api-address',
        help='"host:port" for the RPC server to listen on.',
        default='127.0.0.1:5001',
        type=str,
        show_default=True,
    ),
    click.option(
        '--datadir',
        help='Directory for storing raiden data.',
        default=os.path.join(os.path.expanduser('~'), '.raiden'),
        type=click.Path(
            exists=False,
            dir_okay=True,
            file_okay=False,
            writable=True,
            resolve_path=True,
            allow_dash=False,
        ),
        show_default=True,
    ),
    click.option(
        '--password-file',
        help='Text file containing the password for the provided account',
        default=None,
        type=click.File(lazy=True),
        show_default=True,
    ),
    click.option(
        '--web-ui/--no-web-ui',
        help=(
            'Start with or without the web interface. Requires --rpc. '
            'It will be accessible at http://<api-address>. '
        ),
        default=True,
        show_default=True,
    ),
    click.option(
        '--eth-client-communication',
        help='Print all communication with the underlying eth client',
        is_flag=True,
    ),
    click.option(
        '--nat',
        help='Manually specify method to use for determining public IP / NAT traversal.\n'
             'Available methods:\n'
             '"auto" - Try UPnP, then STUN, fallback to none\n'
             '"upnp" - Try UPnP, fallback to none\n'
             '"stun" - Try STUN, fallback to none\n'
             '"none" - Use the local interface address '
             '(this will likely cause connectivity issues)\n'
             '"ext:<IP>[:<PORT>]" - manually specify the external IP (and optionally port no.)',
        type=NATChoiceType(['auto', 'upnp', 'stun', 'none', 'ext:<IP>[:<PORT>]']),
        default='auto',
        show_default=True
    )
]


def options(func):
    """Having the common app options as a decorator facilitates reuse.
    """
    for option in OPTIONS:
        func = option(func)
    return func


@options
@click.command()
def app(
        address,
        keystore_path,
        gas_price,
        eth_rpc_endpoint,
        registry_contract_address,
        discovery_contract_address,
        listen_address,
        rpccorsdomain,
        mapped_socket,
        logging,
        logfile,
        log_json,
        max_unresponsive_time,
        send_ping_time,
        api_address,
        rpc,
        sync_check,
        console,
        password_file,
        web_ui,
        datadir,
        eth_client_communication,
        nat):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    from raiden.app import App
    from raiden.network.blockchain_service import BlockChainService

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

    config['protocol']['nat_keepalive_retries'] = DEFAULT_NAT_KEEPALIVE_RETRIES
    timeout = max_unresponsive_time / DEFAULT_NAT_KEEPALIVE_RETRIES
    config['protocol']['nat_keepalive_timeout'] = timeout

    address_hex = address_encoder(address) if address else None
    address_hex, privatekey_bin = prompt_account(address_hex, keystore_path, password_file)
    address = address_decoder(address_hex)

    privatekey_hex = hexlify(privatekey_bin)
    config['privatekey_hex'] = privatekey_hex

    endpoint = eth_rpc_endpoint

    # Fallback to default port if only an IP address is given
    rpc_port = 8545
    if eth_rpc_endpoint.startswith('http://'):
        endpoint = eth_rpc_endpoint[len('http://'):]
        rpc_port = 80
    elif eth_rpc_endpoint.startswith('https://'):
        endpoint = eth_rpc_endpoint[len('https://'):]
        rpc_port = 443

    if ':' not in endpoint:  # no port was given in url
        rpc_host = endpoint
    else:
        rpc_host, rpc_port = split_endpoint(endpoint)

    rpc_client = JSONRPCClient(
        rpc_host,
        rpc_port,
        privatekey_bin,
        gas_price,
    )

    # this assumes the eth node is already online
    if not check_json_rpc(rpc_client):
        sys.exit(1)

    blockchain_service = BlockChainService(
        privatekey_bin,
        rpc_client,
        gas_price,
    )

    if sync_check:
        check_synced(blockchain_service)

    discovery_tx_cost = rpc_client.gasprice() * DISCOVERY_TX_GAS_LIMIT
    while True:
        balance = blockchain_service.client.balance(address)
        if discovery_tx_cost <= balance:
            break
        print(
            'Account has insufficient funds for discovery registration.\n'
            'Needed: {} ETH\n'
            'Available: {} ETH.\n'
            'Please deposit additional funds into this account.'
            .format(discovery_tx_cost / denoms.ether, balance / denoms.ether)
        )
        if not click.confirm('Try again?'):
            sys.exit(1)

    registry = blockchain_service.registry(
        registry_contract_address,
    )

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

    return App(
        config,
        blockchain_service,
        registry,
        discovery,
    )


def prompt_account(address_hex, keystore_path, password_file):
    accmgr = AccountManager(keystore_path)
    if not accmgr.accounts:
        raise RuntimeError('No Ethereum accounts found in the user\'s system')

    if not accmgr.address_in_keystore(address_hex):
        # check if an address has been passed
        if address_hex is not None:
            print("Account '{}' could not be found on the system. Aborting ...".format(
                address_hex))
            sys.exit(1)

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
            print('Incorrect password for {} in file. Aborting ...'.format(address_hex))
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
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if ctx.invoked_subcommand is None:
        print('Welcome to Raiden, version {}!'.format(get_system_spec()['raiden']))
        from raiden.ui.console import Console
        from raiden.api.python import RaidenAPI

        slogging.configure(
            kwargs['logging'],
            log_json=kwargs['log_json'],
            log_file=kwargs['logfile']
        )
        if kwargs['logfile']:
            # Disable stream logging
            root = slogging.getLogger()
            for handler in root.handlers:
                if isinstance(handler, slogging.logging.StreamHandler):
                    root.handlers.remove(handler)
                    break

        # TODO:
        # - Ask for confirmation to quit if there are any locked transfers that did
        # not timeout.
        (listen_host, listen_port) = split_endpoint(kwargs['listen_address'])
        try:
            with SocketFactory(listen_host, listen_port, strategy=kwargs['nat']) as mapped_socket:
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
                        eth_rpc_endpoint=ctx.params['eth_rpc_endpoint'],
                    )
                    (api_host, api_port) = split_endpoint(kwargs['api_address'])
                    api_server.start(api_host, api_port)

                    print(
                        'The Raiden API RPC server is now running at http://{}:{}/.\n\n'
                        'See the Raiden documentation for all available endpoints at\n'
                        'http://raiden-network.readthedocs.io/en/stable/rest_api.html'.format(
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

                gevent.signal(signal.SIGUSR1, toogle_cpu_profiler)
                gevent.signal(signal.SIGUSR2, toggle_trace_profiler)

                event.wait()
                print('Signal received. Shutting down ...')
                try:
                    api_server.stop()
                except NameError:
                    pass
        except socket.error as v:
            if v.args[0] == errno.EADDRINUSE:
                print('ERROR: Address %s:%s is in use. '
                      'Use --listen-address <host:port> to specify port to listen on.' %
                      (listen_host, listen_port))
                sys.exit(1)
            raise
        app_.stop(leave_channels=False)
    else:
        # Pass parsed args on to subcommands.
        ctx.obj = kwargs


@run.command()
@click.option(
    '--short',
    is_flag=True,
    help='Only display Raiden version'
)
def version(short, **kwargs):
    """Print version information and exit. """
    if short:
        print(get_system_spec()['raiden'])
    else:
        print(json.dumps(
            get_system_spec(),
            indent=2
        ))


@run.command()
@click.option(
    '--debug',
    is_flag=True,
    help='Drop into pdb on errors.'
)
@click.pass_context
def smoketest(ctx, debug, **kwargs):
    """ Test, that the raiden installation is sane.
    """
    from raiden.api.python import RaidenAPI
    from raiden.blockchain.abi import get_static_or_compile
    from raiden.utils import get_contract_path

    # Check the solidity compiler early in the smoketest.
    #
    # Binary distributions don't need the solidity compiler but source
    # distributions do. Since this is checked by `get_static_or_compile`
    # function, use it as a proxy for validating the setup.
    get_static_or_compile(
        get_contract_path('HumanStandardToken.sol'),
        'HumanStandardToken',
    )

    report_file = tempfile.mktemp(suffix='.log')
    open(report_file, 'w+')

    def append_report(subject, data):
        with open(report_file, 'a', encoding='UTF-8') as handler:
            handler.write('{:=^80}'.format(' %s ' % subject.upper()) + os.linesep)
            if data is not None:
                if isinstance(data, bytes):
                    data = data.decode()
                handler.writelines([data + os.linesep])

    append_report('raiden version', json.dumps(get_system_spec()))
    append_report('raiden log', None)

    print('[1/5] getting smoketest configuration')
    smoketest_config = load_or_create_smoketest_config()

    print('[2/5] starting ethereum')
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
    args['api_address'] = 'localhost:' + str(next(get_free_port('127.0.0.1', 5001)))
    args['sync_check'] = False

    # invoke the raiden app
    app_ = ctx.invoke(app, **args)

    raiden_api = RaidenAPI(app_.raiden)
    rest_api = RestAPI(raiden_api)
    api_server = APIServer(rest_api)
    (api_host, api_port) = split_endpoint(args['api_address'])
    api_server.start(api_host, api_port)

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


@run.command()
@click.pass_context
def removedb(ctx):
    """
    Delete local cache and database of this address or all if none is specified.
    """
    import shutil

    datadir = ctx.obj['datadir']
    address = ctx.obj['address']
    address_hex = address_encoder(address) if address else None
    user_db_dir = os.path.join(datadir, address_hex[:8]) if address_hex else datadir

    if not os.path.exists(user_db_dir):
        print('Directory does not exist: {}'.format(user_db_dir))
        print('Nothing to delete.')
        return

    # Sanity check if the specified directory is a Raiden datadir.
    sane = True
    if not address_hex:
        regex = init_minified_addr_checker()
        ls = os.listdir(user_db_dir)
        sane = all(
            check_minified_address(f, regex) and
            len(f) == 8 and
            os.path.isdir(os.path.join(user_db_dir, f))
            for f in ls
        )

    if not sane:
        print('WARNING: The specified directory does not appear to be a Raiden data directory.')

    prompt = 'Are you sure you want to delete {}?'.format(user_db_dir)

    if click.confirm(prompt):
        shutil.rmtree(user_db_dir)
        print('Local data deleted.')
    else:
        print('Abort.')
