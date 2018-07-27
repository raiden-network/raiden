import gevent.monkey
gevent.monkey.patch_all()

import json
import os
import signal
import sys
import tempfile
import textwrap
import traceback
from binascii import hexlify
from copy import deepcopy
from datetime import datetime
from itertools import count
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict
from urllib.parse import urljoin

import click
import gevent
import requests
import structlog
from eth_utils import (
    denoms,
    to_canonical_address,
    to_checksum_address,
    to_int,
    to_normalized_address,
)
from mirakuru import HTTPExecutor, ProcessExitedWithError
from requests.exceptions import RequestException

from raiden import constants
from raiden.accounts import AccountManager
from raiden.api.rest import APIServer, RestAPI
from raiden.exceptions import (
    APIServerPortInUseError,
    ContractVersionMismatch,
    EthNodeCommunicationError,
    RaidenError,
    RaidenServicePortInUseError,
    ReplacementTransactionUnderpriced,
)
from raiden.log_config import configure_logging
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.proxies import TokenNetworkRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.sockfactory import SocketFactory
from raiden.network.throttle import TokenBucket
from raiden.network.transport import MatrixTransport, UDPTransport
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_TRANSPORT_RETRY_INTERVAL,
    ETHERSCAN_API,
    INITIAL_PORT,
    ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE,
)
from raiden.tasks import check_version
from raiden.utils import (
    eth_endpoint_to_hostport,
    get_system_spec,
    merge_dict,
    split_endpoint,
    typing,
)
from raiden.utils.cli import (
    ADDRESS_TYPE,
    LOG_LEVEL_CONFIG_TYPE,
    MatrixServerType,
    NATChoiceType,
    NetworkChoiceType,
    PathRelativePath,
    apply_config_file,
    group,
    option,
    option_group,
)
from raiden.utils.echo_node import EchoNode
from raiden.utils.gevent_utils import configure_gevent
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
)


log = structlog.get_logger(__name__)

configure_gevent()


def check_synced(blockchain_service: BlockChainService) -> None:
    net_id = blockchain_service.network_id
    try:
        network = constants.ID_TO_NETWORKNAME[net_id]
    except (EthNodeCommunicationError, RequestException):
        print(
            'Could not determine the network the ethereum node is connected.\n'
            'Because of this there is no way to determine the latest\n'
            'block with an oracle, and the events from the ethereum\n'
            'node cannot be trusted. Giving up.\n',
        )
        sys.exit(1)
    except KeyError:
        print(
            'Your ethereum client is connected to a non-recognized private \n'
            'network with network-ID {}. Since we can not check if the client \n'
            'is synced please restart raiden with the --no-sync-check argument.'
            '\n'.format(net_id),
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


def check_discovery_registration_gas(
        blockchain_service: BlockChainService,
        account_address: typing.Address,
) -> None:
    discovery_tx_cost = blockchain_service.client.gasprice() * constants.DISCOVERY_TX_GAS_LIMIT
    account_balance = blockchain_service.client.balance(account_address)

    if discovery_tx_cost > account_balance:
        print(
            'Account has insufficient funds for discovery registration.\n'
            'Needed: {} ETH\n'
            'Available: {} ETH.\n'
            'Please deposit additional funds into this account.'
            .format(discovery_tx_cost / denoms.ether, account_balance / denoms.ether),
        )
        sys.exit(1)


def etherscan_query_with_retries(
        url: str,
        sleep: float,
        retries: int = 3,
) -> int:
    for _ in range(retries - 1):
        try:
            etherscan_block = to_int(hexstr=requests.get(url).json()['result'])
        except (RequestException, ValueError, KeyError):
            gevent.sleep(sleep)
        else:
            return etherscan_block

    etherscan_block = to_int(hexstr=requests.get(url).json()['result'])
    return etherscan_block


def wait_for_sync_etherscan(
        blockchain_service: BlockChainService,
        url: str,
        tolerance: int,
        sleep: float,
) -> None:
    local_block = blockchain_service.client.block_number()
    etherscan_block = etherscan_query_with_retries(url, sleep)
    syncing_str = '\rSyncing ... Current: {} / Target: ~{}'

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

        print(syncing_str.format(local_block, etherscan_block), end='')

    # add a newline so that the next print will start have it's own line
    print('')


def wait_for_sync_rpc_api(
        blockchain_service: BlockChainService,
        sleep: float,
) -> None:
    if blockchain_service.is_synced():
        return

    print('Waiting for the ethereum node to synchronize [Use ^C to exit].')

    for i in count():
        if i % 3 == 0:
            print('\r', end='')

        print('.', end='')
        sys.stdout.flush()

        gevent.sleep(sleep)

        if blockchain_service.is_synced():
            return

    # add a newline so that the next print will start have it's own line
    print('')


def wait_for_sync(
        blockchain_service: BlockChainService,
        url: str,
        tolerance: int,
        sleep: float,
) -> None:
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
            '--config-file',
            help='Configuration file (TOML)',
            default=os.path.join('${datadir}', 'config.toml'),
            type=PathRelativePath(
                file_okay=True,
                dir_okay=False,
                exists=False,
                readable=True,
                resolve_path=True,
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
            default=constants.ROPSTEN_REGISTRY_ADDRESS,  # testnet default
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--secret-registry-contract-address',
            help='hex encoded address of the secret registry contract.',
            default=constants.ROPSTEN_SECRET_REGISTRY_ADDRESS,  # testnet default
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--discovery-contract-address',
            help='hex encoded address of the discovery contract.',
            default=constants.ROPSTEN_DISCOVERY_ADDRESS,  # testnet default
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--console',
            help='Start the interactive raiden console',
            is_flag=True,
        ),
        option(
            '--transport',
            help='Transport system to use. Matrix is experimental.',
            type=click.Choice(['udp', 'matrix']),
            default='matrix',
            show_default=True,
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
                type=int,
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
                option_group='udp_transport',
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
            ),
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
                is_flag=True,
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


def run_app(
        address,
        keystore_path,
        gas_price,
        eth_rpc_endpoint,
        registry_contract_address,
        secret_registry_contract_address,
        discovery_contract_address,
        listen_address,
        mapped_socket,
        max_unresponsive_time,
        api_address,
        rpc,
        sync_check,
        console,
        password_file,
        web_ui,
        datadir,
        transport,
        matrix_server,
        network_id,
        extra_config=None,
        **kwargs,
):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    from raiden.app import App

    if transport == 'udp' and not mapped_socket:
        raise RuntimeError('Missing socket')

    address_hex = to_normalized_address(address) if address else None
    address_hex, privatekey_bin = prompt_account(address_hex, keystore_path, password_file)
    address = to_canonical_address(address_hex)

    (listen_host, listen_port) = split_endpoint(listen_address)
    (api_host, api_port) = split_endpoint(api_address)

    if datadir is None:
        datadir = os.path.join(os.path.expanduser('~'), '.raiden')

    config = deepcopy(App.DEFAULT_CONFIG)
    if extra_config:
        merge_dict(config, extra_config)

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

    rpc_host, rpc_port = eth_endpoint_to_hostport(eth_rpc_endpoint)

    rpc_client = JSONRPCClient(
        rpc_host,
        rpc_port,
        privatekey_bin,
        gas_price,
    )

    blockchain_service = BlockChainService(privatekey_bin, rpc_client)

    net_id = blockchain_service.network_id
    if net_id != network_id:
        if network_id in constants.ID_TO_NETWORKNAME and net_id in constants.ID_TO_NETWORKNAME:
            print((
                "The chosen ethereum network '{}' differs from the ethereum client '{}'. "
                'Please update your settings.'
            ).format(constants.ID_TO_NETWORKNAME[network_id], constants.ID_TO_NETWORKNAME[net_id]))
        else:
            print((
                "The chosen ethereum network id '{}' differs from the ethereum client '{}'. "
                'Please update your settings.'
            ).format(network_id, net_id))
        sys.exit(1)

    config['chain_id'] = network_id

    if sync_check:
        check_synced(blockchain_service)

    database_path = os.path.join(datadir, 'netid_%s' % net_id, address_hex[:8], 'log.db')
    config['database_path'] = database_path
    print(
        '\nYou are connected to the \'{}\' network and the DB path is: {}'.format(
            constants.ID_TO_NETWORKNAME.get(net_id) or net_id,
            database_path,
        ),
    )

    try:
        token_network_registry = blockchain_service.token_network_registry(
            registry_contract_address,
        )
    except ContractVersionMismatch:
        print(
            'Deployed registry contract version mismatch. '
            'Please update your Raiden installation.',
        )
        sys.exit(1)

    try:
        secret_registry = blockchain_service.secret_registry(
            secret_registry_contract_address,
        )
    except ContractVersionMismatch:
        print(
            'Deployed secret registry contract version mismatch. '
            'Please update your Raiden installation.',
        )
        sys.exit(1)

    discovery = None
    if transport == 'udp':
        check_discovery_registration_gas(blockchain_service, address)
        try:
            discovery = ContractDiscovery(
                blockchain_service.node_address,
                blockchain_service.discovery(discovery_contract_address),
            )
        except ContractVersionMismatch:
            print('Deployed discovery contract version mismatch. '
                  'Please update your Raiden installation.')
            sys.exit(1)
        throttle_policy = TokenBucket(
            config['transport']['throttle_capacity'],
            config['transport']['throttle_fill_rate'],
        )

        transport = UDPTransport(
            discovery,
            mapped_socket.socket,
            throttle_policy,
            config['transport'],
        )
    elif transport == 'matrix':
        # matrix gets spammed with the default retry-interval of 1s, wait a little more
        if config['transport']['retry_interval'] == DEFAULT_TRANSPORT_RETRY_INTERVAL:
            config['transport']['retry_interval'] *= 5
        try:
            transport = MatrixTransport(config['matrix'])
        except RaidenError as ex:
            click.secho(f'FATAL: {ex}', fg='red')
            sys.exit(1)
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    try:
        raiden_app = App(
            config=config,
            chain=blockchain_service,
            query_start_block=constants.ID_TO_QUERY_BLOCK[net_id],
            default_registry=token_network_registry,
            default_secret_registry=secret_registry,
            transport=transport,
            discovery=discovery,
        )
    except RaidenError as e:
        click.secho(f'FATAL: {e}', fg='red')
        sys.exit(1)

    return raiden_app


def prompt_account(address_hex, keystore_path, password_file):
    accmgr = AccountManager(keystore_path)
    if not accmgr.accounts:
        print(
            'No Ethereum accounts found in the provided keystore directory {}. '
            'Please provide a directory containing valid ethereum account '
            'files.'.format(keystore_path),
        )
        sys.exit(1)

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
        password = password_file.read()
        if password != '':
            password = password.splitlines()[0]
    if password is not None:
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
                        .format(address_hex),
                    )
                    sys.exit(1)

                print(
                    'Incorrect passphrase to unlock the private key. {} tries remaining. '
                    'Please try again or kill the process to quit. '
                    'Usually Ctrl-c.'.format(unlock_tries),
                )
                unlock_tries -= 1

    return address_hex, privatekey_bin


class NodeRunner:
    def __init__(self, options: Dict[str, Any], ctx):
        self._options = options
        self._ctx = ctx
        self._raiden_api = None

    @property
    def _welcome_string(self):
        return f"Welcome to Raiden, version {get_system_spec()['raiden']}!"

    def _startup_hook(self):
        """ Hook that is called after startup is finished. Intended for subclass usage. """
        pass

    def _shutdown_hook(self):
        """ Hook that is called just before shutdown. Intended for subclass usage. """
        pass

    def run(self):
        click.secho(self._welcome_string, fg='green')
        click.secho(
            textwrap.dedent(
                '''\
                ----------------------------------------------------------------------
                | This is an Alpha version of experimental open source software      |
                | released under the MIT license and may contain errors and/or bugs. |
                | Use of the software is at your own risk and discretion. No         |
                | guarantee whatsoever is made regarding its suitability for your    |
                | intended purposes and its compliance with applicable law and       |
                | regulations. It is up to the user to determine the software´s      |
                | quality and suitability and whether its use is compliant with its  |
                | respective regulatory regime, especially in the case that you are  |
                | operating in a commercial context.                                 |
                ----------------------------------------------------------------------''',
            ),
            fg='yellow',
        )
        configure_logging(
            self._options['log_config'],
            log_json=self._options['log_json'],
            log_file=self._options['log_file'],
        )

        if self._options['config_file']:
            log.debug('Using config file', config_file=self._options['config_file'])

        # TODO:
        # - Ask for confirmation to quit if there are any locked transfers that did
        # not timeout.
        try:
            if self._options['transport'] == 'udp':
                (listen_host, listen_port) = split_endpoint(self._options['listen_address'])
                try:
                    with SocketFactory(
                        listen_host, listen_port, strategy=self._options['nat'],
                    ) as mapped_socket:
                        self._options['mapped_socket'] = mapped_socket
                        app = self._run_app()

                except RaidenServicePortInUseError:
                    print(
                        'ERROR: Address %s:%s is in use. '
                        'Use --listen-address <host:port> to specify port to listen on.' %
                        (listen_host, listen_port),
                    )
                    sys.exit(1)
            elif self._options['transport'] == 'matrix':
                self._options['mapped_socket'] = None
                app = self._run_app()
            else:
                # Shouldn't happen
                raise RuntimeError(f"Invalid transport type '{self._options['transport']}'")
            app.stop(leave_channels=False)
        except ReplacementTransactionUnderpriced as e:
            print(
                '{}. Please make sure that this Raiden node is the '
                'only user of the selected account'.format(str(e)),
            )
            sys.exit(1)

    def _run_app(self):
        from raiden.ui.console import Console
        from raiden.api.python import RaidenAPI

        # this catches exceptions raised when waiting for the stalecheck to complete
        try:
            app_ = run_app(**self._options)
        except EthNodeCommunicationError:
            print(
                '\n'
                'Could not contact the ethereum node through JSON-RPC.\n'
                'Please make sure that JSON-RPC is enabled for these interfaces:\n'
                '\n'
                '    eth_*, net_*, web3_*\n'
                '\n'
                'geth: https://github.com/ethereum/go-ethereum/wiki/Management-APIs\n',
            )
            sys.exit(1)

        domain_list = []
        if self._options['rpccorsdomain']:
            if ',' in self._options['rpccorsdomain']:
                for domain in self._options['rpccorsdomain'].split(','):
                    domain_list.append(str(domain))
            else:
                domain_list.append(str(self._options['rpccorsdomain']))

        self._raiden_api = RaidenAPI(app_.raiden)

        api_server = None
        if self._options['rpc']:
            rest_api = RestAPI(self._raiden_api)
            api_server = APIServer(
                rest_api,
                cors_domain_list=domain_list,
                web_ui=self._options['web_ui'],
                eth_rpc_endpoint=self._options['eth_rpc_endpoint'],
            )
            (api_host, api_port) = split_endpoint(self._options['api_address'])

            try:
                api_server.start(api_host, api_port)
            except APIServerPortInUseError:
                print(
                    'ERROR: API Address %s:%s is in use. '
                    'Use --api-address <host:port> to specify port to listen on.' %
                    (api_host, api_port),
                )
                sys.exit(1)

            print(
                'The Raiden API RPC server is now running at http://{}:{}/.\n\n'
                'See the Raiden documentation for all available endpoints at\n'
                'http://raiden-network.readthedocs.io/en/stable/rest_api.html'.format(
                    api_host,
                    api_port,
                ),
            )

        if self._options['console']:
            console = Console(app_)
            console.start()

        # spawning a thread to handle the version checking
        gevent.spawn(check_version)

        self._startup_hook()

        # wait for interrupt
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)

        try:
            event.wait()
            print('Signal received. Shutting down ...')
        except RaidenError as ex:
            click.secho(f'FATAL: {ex}', fg='red')
        except Exception as ex:
            with NamedTemporaryFile(
                'w',
                prefix=f'raiden-exception-{datetime.utcnow():%Y-%m-%dT%H-%M}',
                suffix='.txt',
                delete=False,
            ) as traceback_file:
                traceback.print_exc(file=traceback_file)
                click.secho(
                    f'FATAL: An unexpected exception occured.'
                    f'A traceback has been written to {traceback_file.name}\n'
                    f'{ex}',
                    fg='red',
                )
        finally:
            self._shutdown_hook()
            if api_server:
                api_server.stop()

        return app_


class EchoNodeRunner(NodeRunner):
    def __init__(self, options: Dict[str, Any], ctx, token_address: typing.TokenAddress):
        super().__init__(options, ctx)
        self._token_address = token_address
        self._echo_node = None

    @property
    def _welcome_string(self):
        return '{} [ECHO NODE]'.format(super(EchoNodeRunner, self)._welcome_string)

    def _startup_hook(self):
        self._echo_node = EchoNode(self._raiden_api, self._token_address)

    def _shutdown_hook(self):
        self._echo_node.stop()


@group(invoke_without_command=True, context_settings={'max_content_width': 120})
@options
@click.pass_context
def run(ctx, **kwargs):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if kwargs['config_file']:
        apply_config_file(run, kwargs, ctx)

    if ctx.invoked_subcommand is not None:
        # Pass parsed args on to subcommands.
        ctx.obj = kwargs
        return

    NodeRunner(kwargs, ctx).run()


@run.command()
@option(
    '--short',
    is_flag=True,
    help='Only display Raiden version',
)
def version(short, **kwargs):  # pylint: disable=unused-argument
    """Print version information and exit. """
    if short:
        print(get_system_spec()['raiden'])
    else:
        print(json.dumps(
            get_system_spec(),
            indent=2,
        ))


@run.command()
@option(
    '--debug',
    is_flag=True,
    help='Drop into pdb on errors.',
)
@option(
    '--local-matrix',
    help='Command-line to be used to run a local matrix server (or "none")',
    default=str(Path(__file__).parent.parent.parent.joinpath('.synapse', 'run_synapse.sh')),
    show_default=True,
)
@click.pass_context
def smoketest(ctx, debug, local_matrix, **kwargs):  # pylint: disable=unused-argument
    """ Test, that the raiden installation is sane. """
    import binascii
    from web3 import Web3, HTTPProvider
    from web3.middleware import geth_poa_middleware
    from raiden.api.python import RaidenAPI
    from raiden.tests.utils.geth import geth_wait_and_check
    from raiden.tests.integration.contracts.fixtures.contracts import deploy_token
    from raiden.tests.utils.smoketest import (
        TEST_PARTNER_ADDRESS,
        TEST_DEPOSIT_AMOUNT,
        deploy_smoketest_contracts,
        get_private_key,
        load_smoketest_config,
        start_ethereum,
        run_smoketests,
    )

    report_file = tempfile.mktemp(suffix='.log')
    configure_logging({'': 'DEBUG'}, log_file=report_file)

    def append_report(subject, data):
        with open(report_file, 'a', encoding='UTF-8') as handler:
            handler.write(f'{f" {subject.upper()} ":=^80}{os.linesep}')
            if data is not None:
                if isinstance(data, bytes):
                    data = data.decode()
                handler.writelines([data + os.linesep])

    append_report('Raiden version', json.dumps(get_system_spec()))
    append_report('Raiden log', None)

    step_count = 7
    if ctx.parent.params['transport'] == 'matrix':
        step_count = 8
    step = 0

    def print_step(description, error=False):
        nonlocal step
        step += 1
        click.echo(
            '{} {}'.format(
                click.style(f'[{step}/{step_count}]', fg='blue'),
                click.style(description, fg='green' if not error else 'red'),
            ),
        )

    print_step('Getting smoketest configuration')
    smoketest_config = load_smoketest_config()
    if not smoketest_config:
        append_report(
            'Smoketest configuration',
            'Could not load the smoketest genesis configuration file.',
        )

    print_step('Starting Ethereum node')
    ethereum, ethereum_config = start_ethereum(smoketest_config['genesis'])
    port = ethereum_config['rpc']
    web3_client = Web3(HTTPProvider(f'http://0.0.0.0:{port}'))
    web3_client.middleware_stack.inject(geth_poa_middleware, layer=0)
    random_marker = binascii.hexlify(b'raiden').decode()
    privatekeys = []
    geth_wait_and_check(web3_client, privatekeys, random_marker)

    print_step('Deploying Raiden contracts')
    host = '0.0.0.0'
    client = JSONRPCClient(
        host,
        ethereum_config['rpc'],
        get_private_key(),
        web3=web3_client,
    )
    contract_addresses = deploy_smoketest_contracts(client, 627)

    token_contract = deploy_token(client)
    token = token_contract(1000, 0, 'TKN', 'TKN')

    registry = TokenNetworkRegistry(client, contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY])

    registry.add_token(to_canonical_address(token.contract.address))

    print_step('Setting up Raiden')
    # setup cli arguments for starting raiden
    args = dict(
        discovery_contract_address=to_checksum_address(
            contract_addresses[CONTRACT_ENDPOINT_REGISTRY],
        ),
        registry_contract_address=to_checksum_address(
            contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
        ),
        secret_registry_contract_address=to_checksum_address(
            contract_addresses[CONTRACT_SECRET_REGISTRY],
        ),
        eth_rpc_endpoint='http://127.0.0.1:{}'.format(port),
        keystore_path=ethereum_config['keystore'],
        address=ethereum_config['address'],
        network_id='627',
        transport=ctx.parent.params['transport'],
        matrix_server='http://localhost:8008'
                      if ctx.parent.params['matrix_server'] == 'auto'
                      else ctx.parent.params['matrix_server'],
    )
    smoketest_config['transport'] = args['transport']
    for option_ in run.params:
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

    def _run_smoketest():
        print_step('Starting Raiden')

        # invoke the raiden app
        app = run_app(**args)

        raiden_api = RaidenAPI(app.raiden)
        rest_api = RestAPI(raiden_api)
        api_server = APIServer(rest_api)
        (api_host, api_port) = split_endpoint(args['api_address'])
        api_server.start(api_host, api_port)

        raiden_api.channel_open(
            contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
            to_canonical_address(token.contract.address),
            to_canonical_address(TEST_PARTNER_ADDRESS),
            None,
            None,
        )
        raiden_api.set_total_channel_deposit(
            contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
            to_canonical_address(token.contract.address),
            to_canonical_address(TEST_PARTNER_ADDRESS),
            TEST_DEPOSIT_AMOUNT,
        )

        smoketest_config['contracts']['registry_address'] = to_checksum_address(
            contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
        )
        smoketest_config['contracts']['secret_registry_address'] = to_checksum_address(
            contract_addresses[CONTRACT_SECRET_REGISTRY],
        )
        smoketest_config['contracts']['discovery_address'] = to_checksum_address(
            contract_addresses[CONTRACT_ENDPOINT_REGISTRY],
        )
        smoketest_config['contracts']['token_address'] = to_checksum_address(
            token.contract.address,
        )

        success = False
        try:
            print_step('Running smoketest')
            error = run_smoketests(app.raiden, smoketest_config, debug=debug)
            if error is not None:
                append_report('Smoketest assertion error', error)
            else:
                success = True
        finally:
            app.stop()
            ethereum.send_signal(2)

            err, out = ethereum.communicate()
            append_report('Ethereum init stdout', ethereum_config['init_log_out'].decode('utf-8'))
            append_report('Ethereum init stderr', ethereum_config['init_log_err'].decode('utf-8'))
            append_report('Ethereum stdout', out)
            append_report('Ethereum stderr', err)
            append_report('Smoketest configuration', json.dumps(smoketest_config))
        if success:
            print_step(f'Smoketest successful, report was written to {report_file}')
        else:
            print_step(f'Smoketest had errors, report was written to {report_file}', error=True)
        return success

    if args['transport'] == 'udp':
        with SocketFactory('127.0.0.1', port, strategy='none') as mapped_socket:
            args['mapped_socket'] = mapped_socket
            success = _run_smoketest()
    elif args['transport'] == 'matrix' and local_matrix.lower() != 'none':
        args['mapped_socket'] = None
        print_step('Starting Matrix transport')
        try:
            with HTTPExecutor(
                local_matrix,
                status=r'^[24]\d\d$',
                url=urljoin(args['matrix_server'], '/_matrix/client/versions'),
                shell=True,
            ):
                args['extra_config'] = {
                    'matrix': {
                        'discovery_room': {'server': 'matrix.local.raiden'},
                        'server_name': 'matrix.local.raiden',
                    },
                }
                success = _run_smoketest()
        except (PermissionError, ProcessExitedWithError):
            append_report('Matrix server start exception', traceback.format_exc())
            print_step(
                f'Error during smoketest setup, report was written to {report_file}',
                error=True,
            )
            success = False
    elif args['transport'] == 'matrix' and local_matrix.lower() == "none":
        args['mapped_socket'] = None
        success = _run_smoketest()
    else:
        # Shouldn't happen
        raise RuntimeError(f"Invalid transport type '{args['transport']}'")

    if not success:
        sys.exit(1)


@run.command(
    help=(
        'Start an echo node.\n'
        'Mainly useful for development.\n'
        'See: https://raiden-network.readthedocs.io/en/stable/api_walkthrough.html'
        '#interacting-with-the-raiden-echo-node'
    ),
)
@click.option('--token-address', type=ADDRESS_TYPE, required=True)
@click.pass_context
def echonode(ctx, token_address):
    """ Start a raiden Echo Node that will send received transfers back to the initiator. """
    EchoNodeRunner(ctx.obj, ctx, token_address).run()
