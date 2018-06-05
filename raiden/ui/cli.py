# -*- coding: utf-8 -*-
from binascii import hexlify
import sys
import os
import tempfile
import json
import socket
import errno
import signal
import shutil
from copy import deepcopy
from itertools import count

import click
import gevent
import gevent.monkey
gevent.monkey.patch_all()
import requests
from eth_utils import (
    denoms,
    to_checksum_address,
    to_normalized_address,
)
import structlog
from requests.exceptions import RequestException

from raiden.accounts import AccountManager
from raiden.api.rest import APIServer, RestAPI
from raiden.constants import (
    ID_TO_NETWORKNAME,
    ROPSTEN_DISCOVERY_ADDRESS,
    ROPSTEN_REGISTRY_ADDRESS,
)
from raiden.exceptions import EthNodeCommunicationError, ContractVersionMismatch
from raiden.network.discovery import ContractDiscovery
from raiden.network.matrixtransport import MatrixTransport
from raiden.network.transport.udp.udp_transport import UDPTransport
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.sockfactory import SocketFactory
from raiden.network.throttle import TokenBucket
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    ETHERSCAN_API,
    INITIAL_PORT,
    ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE,
)
from raiden.utils import (
    address_decoder,
    get_system_spec,
    is_minified_address,
    is_supported_client,
    quantity_decoder,
    split_endpoint,
)
from raiden.tests.utils.smoketest import (
    load_smoketest_config,
    start_ethereum,
    run_smoketests,
)

from raiden.utils.cli import (
    ADDRESS_TYPE,
    command,
    group,
    MatrixServerType,
    NATChoiceType,
    NetworkChoiceType,
    option,
    option_group,
    LOG_LEVEL_CONFIG_TYPE
)
from raiden.log_config import configure_logging


# ansi escape code for moving the cursor and clearing the line
CURSOR_STARTLINE = '\x1b[1000D'
CLEARLINE = '\x1b[2K'

# 52100 gas is how much registerEndpoint() costs. Rounding to 60k for safety.
DISCOVERY_TX_GAS_LIMIT = 60000


def toogle_cpu_profiler(raiden):
    try:
        from raiden.utils.profiling.cpu import CpuProfiler
    except ImportError:
        structlog.get_logger(__name__).exception('cannot start cpu profiler')
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
        structlog.get_logger(__name__).exception('cannot start tracer profiler')
        return

    if hasattr(raiden, 'profiler') and isinstance(raiden.profiler, TraceProfiler):
        raiden.profiler.stop()
        raiden.profiler = None

    elif not hasattr(raiden, 'profiler') and raiden.config['database_path'] != ':memory:':
        raiden.profiler = TraceProfiler(raiden.config['database_path'])
        raiden.profiler.start()


def check_json_rpc(client):
    try:
        client_version = client.web3.version.node
    except (requests.exceptions.ConnectionError, EthNodeCommunicationError):
        print(
            '\n'
            'Could not contact the ethereum node through JSON-RPC.\n'
            'Please make sure that JSON-RPC is enabled for these interfaces:\n'
            '\n'
            '    eth_*, net_*, web3_*\n'
            '\n'
            'geth: https://github.com/ethereum/go-ethereum/wiki/Management-APIs\n'
        )
        sys.exit(1)
    else:
        if not is_supported_client(client_version):
            print('You need a Byzantium enabled ethereum node. Parity >= 1.7.6 or Geth >= 1.7.2')
            sys.exit(1)


def check_synced(blockchain_service):
    net_id = blockchain_service.network_id
    try:
        network = ID_TO_NETWORKNAME[net_id]
    except (EthNodeCommunicationError, RequestException):
        print(
            'Could not determine the network the ethereum node is connected.\n'
            'Because of this there is no way to determine the latest\n'
            'block with an oracle, and the events from the ethereum\n'
            'node cannot be trusted. Giving up.\n'
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
        network=network if net_id != 1 else 'api',
        action='eth_blockNumber',
    )
    wait_for_sync(
        blockchain_service,
        url=url,
        tolerance=ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE,
        sleep=3,
    )


def check_discovery_registration_gas(blockchain_service, account_address):
    discovery_tx_cost = blockchain_service.client.gasprice() * DISCOVERY_TX_GAS_LIMIT
    account_balance = blockchain_service.client.balance(account_address)

    if discovery_tx_cost > account_balance:
        print(
            'Account has insufficient funds for discovery registration.\n'
            'Needed: {} ETH\n'
            'Available: {} ETH.\n'
            'Please deposit additional funds into this account.'
            .format(discovery_tx_cost / denoms.ether, account_balance / denoms.ether)
        )
        sys.exit(1)


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


def options(func):
    """Having the common app options as a decorator facilitates reuse."""

    # Until https://github.com/pallets/click/issues/926 is fixed the options need to be re-defined
    # for every use
    options_ = [
        option(
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
        option(
            '--keystore-path',
            help=(
                'If you have a non-standard path for the ethereum keystore directory'
                ' provide it using this argument.'
            ),
            default=None,
            type=click.Path(exists=True),
            show_default=True,
        ),
        option(
            '--address',
            help=(
                'The ethereum address you would like raiden to use and for which '
                'a keystore file exists in your local system.'
            ),
            default=None,
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--password-file',
            help='Text file containing the password for the provided account',
            default=None,
            type=click.File(lazy=True),
            show_default=True,
        ),
        option(
            '--registry-contract-address',
            help='hex encoded address of the registry contract.',
            default=ROPSTEN_REGISTRY_ADDRESS,  # testnet default
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--discovery-contract-address',
            help='hex encoded address of the discovery contract.',
            default=ROPSTEN_DISCOVERY_ADDRESS,  # testnet default
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--console',
            help='Start the interactive raiden console',
            is_flag=True
        ),
        option(
            '--transport',
            help='Transport system to use. Matrix is experimental.',
            type=click.Choice(['udp', 'matrix']),
            default='udp',
            show_default=True
        ),
        option(
            '--network-id',
            help=(
                'Specify the network name/id of the Ethereum network to run Raiden on.\n'
                'Available networks:\n'
                '"mainnet" - network id: 1\n'
                '"ropsten" - network id: 3\n'
                '"rinkeby" - network id: 4\n'
                '"kovan" - network id: 42\n'
                '"<NETWORK_ID>": use the given network id directly\n'
            ),
            type=NetworkChoiceType(['mainnet', 'ropsten', 'rinkeby', 'kovan', '<NETWORK_ID>']),
            default='ropsten',
            show_default=True,
        ),
        option_group(
            'Ethereum Node Options',
            option(
                '--sync-check/--no-sync-check',
                help='Checks if the ethereum node is synchronized against etherscan.',
                default=True,
                show_default=True,
            ),
            option(
                '--gas-price',
                help=(
                    'Set the gas price for ethereum transactions. If not provided '
                    'the value of the RPC call eth_gasPrice is going to be used'
                ),
                default=None,
                type=int
            ),
            option(
                '--eth-rpc-endpoint',
                help=(
                    '"host:port" address of ethereum JSON-RPC server.\n'
                    'Also accepts a protocol prefix (http:// or https://) with optional port'
                ),
                default='127.0.0.1:8545',  # geth default jsonrpc port
                type=str,
                show_default=True,
            ),
            option(
                '--eth-client-communication',
                help='Print all communication with the underlying eth client',
                is_flag=True,
            ),
        ),
        option_group(
            'UDP Transport Options',
            option(
                '--listen-address',
                help='"host:port" for the raiden service to listen on.',
                default='0.0.0.0:{}'.format(INITIAL_PORT),
                type=str,
                show_default=True,
            ),
            option(
                '--max-unresponsive-time',
                help=(
                    'Max time in seconds for which an address can send no packets and '
                    'still be considered healthy.'
                ),
                default=30,
                type=int,
                show_default=True,
            ),
            option(
                '--send-ping-time',
                help=(
                    'Time in seconds after which if we have received no message from a '
                    'node we have a connection with, we are going to send a PING message'
                ),
                default=60,
                type=int,
                show_default=True,
            ),
            option(
                '--nat',
                help=(
                    'Manually specify method to use for determining public IP / NAT traversal.\n'
                    'Available methods:\n'
                    '"auto" - Try UPnP, then STUN, fallback to none\n'
                    '"upnp" - Try UPnP, fallback to none\n'
                    '"stun" - Try STUN, fallback to none\n'
                    '"none" - Use the local interface address '
                    '(this will likely cause connectivity issues)\n'
                    '"ext:<IP>[:<PORT>]" - manually specify the external IP (and optionally port '
                    'number)'
                ),
                type=NATChoiceType(['auto', 'upnp', 'stun', 'none', 'ext:<IP>[:<PORT>]']),
                default='auto',
                show_default=True,
                option_group='udp_transport'
            ),
        ),
        option_group(
            'Matrix Transport Options',
            option(
                '--matrix-server',
                help=(
                    'Matrix homeserver to use for communication.\n'
                    'Valid values:\n'
                    '"auto" - automatically select a suitable homeserver\n'
                    'A URL pointing to a Raiden matrix homeserver'
                ),
                default='auto',
                type=MatrixServerType(['auto', '<url>']),
                show_default=True,
            )
        ),
        option_group(
            'Logging Options',
            option(
                '--log-config',
                help='Log level configuration.\n'
                     'Format: [<logger-name-1>]:<level>[,<logger-name-2>:level][,...]',
                type=LOG_LEVEL_CONFIG_TYPE,
                default=':info',
                show_default=True,
            ),
            option(
                '--log-file',
                help='file path for logging to file',
                default=None,
                type=str,
                show_default=True,
            ),
            option(
                '--log-json',
                help='Output log lines in JSON format',
                is_flag=True
            ),
        ),
        option_group(
            'RPC Options',
            option(
                '--rpc/--no-rpc',
                help='Start with or without the RPC server.',
                default=True,
                show_default=True,
            ),
            option(
                '--rpccorsdomain',
                help='Comma separated list of domains to accept cross origin requests.',
                default='http://localhost:*/*',
                type=str,
                show_default=True,
            ),
            option(
                '--api-address',
                help='"host:port" for the RPC server to listen on.',
                default='127.0.0.1:5001',
                type=str,
                show_default=True,
            ),
            option(
                '--web-ui/--no-web-ui',
                help=(
                    'Start with or without the web interface. Requires --rpc. '
                    'It will be accessible at http://<api-address>. '
                ),
                default=True,
                show_default=True,
            ),
        ),
    ]

    for option_ in reversed(options_):
        func = option_(func)
    return func


@options
@command()
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
        log_config,
        log_file,
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
        nat,
        transport,
        matrix_server,
        network_id,
):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    from raiden.app import App
    from raiden.network.blockchain_service import BlockChainService

    if transport == 'udp' and not mapped_socket:
        raise RuntimeError('Missing socket')

    address_hex = to_normalized_address(address) if address else None
    address_hex, privatekey_bin = prompt_account(address_hex, keystore_path, password_file)
    address = address_decoder(address_hex)

    (listen_host, listen_port) = split_endpoint(listen_address)
    (api_host, api_port) = split_endpoint(api_address)

    if datadir is None:
        datadir = os.path.join(os.path.expanduser('~'), '.raiden')

    config = deepcopy(App.DEFAULT_CONFIG)

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
    config['transport_type'] = transport
    config['matrix']['server'] = matrix_server
    config['transport']['nat_keepalive_retries'] = DEFAULT_NAT_KEEPALIVE_RETRIES
    timeout = max_unresponsive_time / DEFAULT_NAT_KEEPALIVE_RETRIES
    config['transport']['nat_keepalive_timeout'] = timeout

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

    blockchain_service = BlockChainService(
        privatekey_bin,
        rpc_client,
        gas_price,
    )

    # this assumes the eth node is already online
    check_json_rpc(rpc_client)

    net_id = blockchain_service.network_id
    if net_id != network_id:
        if network_id in ID_TO_NETWORKNAME and net_id in ID_TO_NETWORKNAME:
            print((
                "The chosen ethereum network '{}' differs from the ethereum client '{}'. "
                'Please update your settings.'
            ).format(ID_TO_NETWORKNAME[network_id], ID_TO_NETWORKNAME[net_id]))
        else:
            print((
                "The chosen ethereum network id '{}' differs from the ethereum client '{}'. "
                'Please update your settings.'
            ).format(network_id, net_id))
        sys.exit(1)

    if sync_check:
        check_synced(blockchain_service)

    database_path = os.path.join(datadir, 'netid_%s' % net_id, address_hex[:8], 'log.db')
    config['database_path'] = database_path
    print(
        'You are connected to the \'{}\' network and the DB path is: {}'.format(
            ID_TO_NETWORKNAME[net_id],
            database_path,
        )
    )

    try:
        registry = blockchain_service.registry(
            registry_contract_address,
        )
    except ContractVersionMismatch:
        print(
            'Deployed registry contract version mismatch. '
            'Please update your Raiden installation.'
        )
        sys.exit(1)

    discovery = None
    if transport == 'udp':
        check_discovery_registration_gas(blockchain_service, address)
        try:
            discovery = ContractDiscovery(
                blockchain_service.node_address,
                blockchain_service.discovery(discovery_contract_address)
            )
        except ContractVersionMismatch:
            print('Deployed discovery contract version mismatch. '
                  'Please update your Raiden installation.')
            sys.exit(1)
        throttle_policy = TokenBucket(
            config['transport']['throttle_capacity'],
            config['transport']['throttle_fill_rate']
        )

        transport = UDPTransport(
            discovery,
            mapped_socket.socket,
            throttle_policy,
            config['transport'],
        )
    elif transport == 'matrix':
        transport = MatrixTransport(config['matrix'])
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    raiden_app = App(
        config,
        blockchain_service,
        registry,
        transport,
        discovery,
    )

    return raiden_app


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
            '[{:3d}] - {}'.format(idx, to_checksum_address(addr))
            for idx, addr in enumerate(addresses)
        ]

        should_prompt = True

        print('The following accounts were found in your machine:')
        print('')
        print('\n'.join(formatted_addresses))
        print('')

        while should_prompt:
            idx = click.prompt('Select one of them by index to continue', type=int)

            if 0 <= idx < len(addresses):
                should_prompt = False
            else:
                print('\nError: Provided index "{}" is out of bounds\n'.format(idx))

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


@group(invoke_without_command=True, context_settings={'max_content_width': 120})
@options
@click.pass_context
def run(ctx, **kwargs):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if ctx.invoked_subcommand is not None:
        # Pass parsed args on to subcommands.
        ctx.obj = kwargs
        return

    print('Welcome to Raiden, version {}!'.format(get_system_spec()['raiden']))
    from raiden.ui.console import Console
    from raiden.api.python import RaidenAPI

    configure_logging(
        kwargs['log_config'],
        log_json=kwargs['log_json'],
        log_file=kwargs['log_file']
    )

    # TODO:
    # - Ask for confirmation to quit if there are any locked transfers that did
    # not timeout.

    def _run_app():
        # this catches exceptions raised when waiting for the stalecheck to complete
        try:
            app_ = ctx.invoke(app, **kwargs)
        except EthNodeCommunicationError as err:
            sys.exit(1)

        domain_list = []
        if kwargs['rpccorsdomain']:
            if ',' in kwargs['rpccorsdomain']:
                for domain in kwargs['rpccorsdomain'].split(','):
                    domain_list.append(str(domain))
            else:
                domain_list.append(str(kwargs['rpccorsdomain']))

        api_server = None
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
        if api_server:
            api_server.stop()

        return app_

    # TODO:
    # - Ask for confirmation to quit if there are any locked transfers that did
    # not timeout.
    if kwargs['transport'] == 'udp':
        (listen_host, listen_port) = split_endpoint(kwargs['listen_address'])
        try:
            with SocketFactory(listen_host, listen_port, strategy=kwargs['nat']) as mapped_socket:
                kwargs['mapped_socket'] = mapped_socket
                app_ = _run_app()

        except socket.error as v:
            if v.args[0] == errno.EADDRINUSE:
                print(
                    'ERROR: Address %s:%s is in use. '
                    'Use --listen-address <host:port> to specify port to listen on.' %
                    (listen_host, listen_port)
                )
                sys.exit(1)
            raise
    elif kwargs['transport'] == 'matrix':
        print('WARNING: The Matrix transport is experimental')
        kwargs['mapped_socket'] = None
        app_ = _run_app()
    else:
        # Shouldn't happen
        raise RuntimeError(f"Invalid transport type '{kwargs['transport']}'")
    app_.stop(leave_channels=False)


@run.command()
@option(
    '--short',
    is_flag=True,
    help='Only display Raiden version'
)
def version(short, **kwargs):  # pylint: disable=unused-argument
    """Print version information and exit. """
    if short:
        print(get_system_spec()['raiden'])
    else:
        print(json.dumps(
            get_system_spec(),
            indent=2
        ))


@run.command()
@option(
    '--debug',
    is_flag=True,
    help='Drop into pdb on errors.'
)
@click.pass_context
def smoketest(ctx, debug, **kwargs):  # pylint: disable=unused-argument
    """ Test, that the raiden installation is sane."""
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
    configure_logging({'': 'DEBUG'}, log_file=report_file)

    def append_report(subject, data):
        with open(report_file, 'a', encoding='UTF-8') as handler:
            handler.write(f'{f" {subject.upper} ":=^80}{os.linesep}')
            if data is not None:
                if isinstance(data, bytes):
                    data = data.decode()
                handler.writelines([data + os.linesep])

    append_report('raiden version', json.dumps(get_system_spec()))
    append_report('raiden log', None)

    print('[1/5] getting smoketest configuration')
    smoketest_config = load_smoketest_config()
    if not smoketest_config:
        append_report(
            'smoketest configuration',
            'Could not load the smoketest genesis configuration file.'
        )

    print('[2/5] starting ethereum')
    ethereum, ethereum_config = start_ethereum(smoketest_config['genesis'])

    print('[3/5] starting raiden')

    # setup cli arguments for starting raiden
    args = dict(
        discovery_contract_address=smoketest_config['contracts']['discovery_address'],
        registry_contract_address=smoketest_config['contracts']['registry_address'],
        eth_rpc_endpoint='http://127.0.0.1:{}'.format(ethereum_config['rpc']),
        keystore_path=ethereum_config['keystore'],
        address=ethereum_config['address'],
        network_id='627',
    )
    for option_ in app.params:
        if option_.name in args.keys():
            args[option_.name] = option_.process_value(ctx, args[option_.name])
        else:
            args[option_.name] = option_.default

    password_file = os.path.join(args['keystore_path'], 'password')
    with open(password_file, 'w') as handler:
        handler.write('password')

    port = next(get_free_port('127.0.0.1', 5001))
    args['password_file'] = click.File()(password_file)
    args['datadir'] = args['keystore_path']
    args['api_address'] = 'localhost:' + str(port)
    args['sync_check'] = False

    with SocketFactory('127.0.0.1', port, strategy='none') as mapped_socket:
        args['mapped_socket'] = mapped_socket

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


def _removedb(netdir, address_hex):
    user_db_dir = os.path.join(netdir, address_hex[:8]) if address_hex else netdir

    if not os.path.exists(user_db_dir):
        return False

    # Sanity check if the specified directory is a Raiden datadir.
    sane = True
    if not address_hex:
        ls = os.listdir(user_db_dir)
        sane = all(
            is_minified_address(f) and
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
        print('Aborted.')

    return True


@run.command()
@click.pass_context
def removedb(ctx):
    """Delete local cache and database of this address or all if none is specified."""

    datadir = ctx.obj['datadir']
    address = ctx.obj['address']
    address_hex = to_normalized_address(address) if address else None

    result = False
    for f in os.listdir(datadir):
        netdir = os.path.join(datadir, f)
        if os.path.isdir(netdir):
            if _removedb(netdir, address_hex):
                result = True

    if not result:
        print('No raiden databases found for {}'.format(address_hex))
        print('Nothing to delete.')
