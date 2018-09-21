import gevent.monkey

gevent.monkey.patch_all()

if True:
    import json
    import os
    import signal
    import sys
    import textwrap
    import traceback
    from binascii import hexlify
    from copy import deepcopy
    from datetime import datetime
    from itertools import count
    from pathlib import Path
    from subprocess import DEVNULL
    from tempfile import NamedTemporaryFile, mktemp
    from typing import Any, Dict
    from urllib.parse import urljoin, urlparse

    import click
    import filelock
    import gevent
    import gevent.monkey
    import requests
    import structlog
    from eth_utils import (
        denoms,
        to_canonical_address,
        to_checksum_address,
        to_int,
        to_normalized_address,
    )
    from gevent.event import AsyncResult
    from mirakuru import ProcessExitedWithError
    from requests.exceptions import (
        ConnectionError as RequestsConnectionError,
        ConnectTimeout,
        RequestException,
    )
    from web3 import HTTPProvider, Web3

    from raiden.constants import (
        DISCOVERY_TX_GAS_LIMIT,
        ID_TO_NETWORKNAME,
        ID_TO_NETWORK_CONFIG,
        NetworkType,
        START_QUERY_BLOCK_KEY,
        SQLITE_MIN_REQUIRED_VERSION,
    )
    from raiden.accounts import AccountManager
    from raiden.api.rest import APIServer, RestAPI
    from raiden.exceptions import (
        AddressWithoutCode,
        AddressWrongContract,
        APIServerPortInUseError,
        ContractVersionMismatch,
        EthNodeCommunicationError,
        RaidenError,
        RaidenServicePortInUseError,
        ReplacementTransactionUnderpriced,
        TransactionAlreadyPending,
    )
    from raiden.log_config import configure_logging
    from raiden.network.blockchain_service import BlockChainService
    from raiden.network.discovery import ContractDiscovery
    from raiden.network.rpc.client import JSONRPCClient
    from raiden.network.sockfactory import SocketFactory
    from raiden.network.throttle import TokenBucket
    from raiden.network.transport import MatrixTransport, UDPTransport
    from raiden.network.utils import get_free_port
    from raiden.raiden_event_handler import RaidenEventHandler
    from raiden.settings import (
        DEFAULT_NAT_KEEPALIVE_RETRIES,
        DEFAULT_SHUTDOWN_TIMEOUT,
        ETHERSCAN_API,
        INITIAL_PORT,
        ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE,
    )
    from raiden.storage.sqlite import RAIDEN_DB_VERSION, assert_sqlite_version
    from raiden.tasks import check_gas_reserve, check_version
    from raiden.utils import (
        get_system_spec,
        is_supported_client,
        merge_dict,
        pex,
        split_endpoint,
        typing,
    )
    from raiden.utils.cli import (
        ADDRESS_TYPE,
        GasPriceChoiceType,
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
    from raiden.utils.http import HTTPExecutor
    from raiden.utils.runnable import Runnable
    from raiden_contracts.constants import (
        CONTRACT_ENDPOINT_REGISTRY,
        CONTRACT_SECRET_REGISTRY,
        CONTRACT_TOKEN_NETWORK_REGISTRY,
    )

log = structlog.get_logger(__name__)


ETHEREUM_NODE_COMMUNICATION_ERROR = (
    '\n'
    'Could not contact the ethereum node through JSON-RPC.\n'
    'Please make sure that JSON-RPC is enabled for these interfaces:\n'
    '\n'
    '    eth_*, net_*, web3_*\n'
    '\n'
    'geth: https://github.com/ethereum/go-ethereum/wiki/Management-APIs\n'
)


def check_synced(blockchain_service: BlockChainService) -> None:
    net_id = blockchain_service.network_id
    try:
        network = ID_TO_NETWORKNAME[net_id]
    except (EthNodeCommunicationError, RequestException):
        click.secho(
            'Could not determine the network the ethereum node is connected.\n'
            'Because of this there is no way to determine the latest\n'
            'block with an oracle, and the events from the ethereum\n'
            'node cannot be trusted. Giving up.\n',
            fg='red',
        )
        sys.exit(1)
    except KeyError:
        click.secho(
            f'Your ethereum client is connected to a non-recognized private \n'
            f'network with network-ID {net_id}. Since we can not check if the client \n'
            f'is synced please restart raiden with the --no-sync-check argument.'
            f'\n',
            fg='red',
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
    discovery_tx_cost = blockchain_service.client.gas_price() * DISCOVERY_TX_GAS_LIMIT
    account_balance = blockchain_service.client.balance(account_address)

    # pylint: disable=no-member
    if discovery_tx_cost > account_balance:
        click.secho(
            'Account has insufficient funds for discovery registration.\n'
            'Needed: {} ETH\n'
            'Available: {} ETH.\n'
            'Please deposit additional funds into this account.'
            .format(discovery_tx_cost / denoms.ether, account_balance / denoms.ether),
            fg='red',
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


def handle_contract_version_mismatch(name: str, address: typing.Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(
        f'Error: Provided {name} {hex_addr} contract version mismatch. '
        'Please update your Raiden installation.',
        fg='red',
    )
    sys.exit(1)


def handle_contract_no_code(name: str, address: typing.Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(f'Error: Provided {name} {hex_addr} contract does not contain code', fg='red')
    sys.exit(1)


def handle_contract_wrong_address(name: str, address: typing.Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(
        f'Error: Provided address {hex_addr} for {name} contract'
        ' does not contain expected code.',
        fg='red',
    )
    sys.exit(1)


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
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--secret-registry-contract-address',
            help='hex encoded address of the secret registry contract.',
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--discovery-contract-address',
            help='hex encoded address of the discovery contract.',
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
        option(
            '--network-type',
            help=(
                'Specify the network type (main or test).\n'
            ),
            type=click.Choice(['main', 'test']),
            default='test',
            show_default=True,
        ),
        option(
            '--accept-disclaimer',
            help='Bypass the experimental software disclaimer prompt',
            is_flag=True,
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
                    'the normal gas price startegy is used.\n'
                    'Available options:\n'
                    '"fast" - transactions are usually mined within 60 seconds\n'
                    '"normal" - transactions are usually mined within 5 minutes\n'
                    '<GAS_PRICE> - use given gas price\n'
                ),
                type=GasPriceChoiceType(['normal', 'fast']),
                default='fast',
                show_default=True,
            ),
            option(
                '--eth-rpc-endpoint',
                help=(
                    '"host:port" address of ethereum JSON-RPC server.\n'
                    'Also accepts a protocol prefix (http:// or https://) with optional port'
                ),
                default='http://127.0.0.1:8545',  # geth default jsonrpc port
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
            option(
                '--disable-debug-logfile',
                help=(
                    'Disable the debug logfile feature. This is independent of '
                    'the normal logging setup'
                ),
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
        network_type,
        extra_config=None,
        **kwargs,
):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    from raiden.app import App

    if not assert_sqlite_version():
        log.error('SQLite3 should be at least version {}'.format(
            '.'.join(SQLITE_MIN_REQUIRED_VERSION),
        ))
        sys.exit(1)

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

    config['transport']['udp']['host'] = listen_host
    config['transport']['udp']['port'] = listen_port
    config['console'] = console
    config['rpc'] = rpc
    config['web_ui'] = rpc and web_ui
    config['api_host'] = api_host
    config['api_port'] = api_port
    if mapped_socket:
        config['socket'] = mapped_socket.socket
        config['transport']['udp']['external_ip'] = mapped_socket.external_ip
        config['transport']['udp']['external_port'] = mapped_socket.external_port
    config['transport_type'] = transport
    config['transport']['matrix']['server'] = matrix_server
    config['transport']['udp']['nat_keepalive_retries'] = DEFAULT_NAT_KEEPALIVE_RETRIES
    timeout = max_unresponsive_time / DEFAULT_NAT_KEEPALIVE_RETRIES
    config['transport']['udp']['nat_keepalive_timeout'] = timeout

    privatekey_hex = hexlify(privatekey_bin)
    config['privatekey_hex'] = privatekey_hex

    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)
    if not parsed_eth_rpc_endpoint.scheme:
        eth_rpc_endpoint = f'http://{eth_rpc_endpoint}'

    web3 = Web3(HTTPProvider(eth_rpc_endpoint))

    try:
        node_version = web3.version.node  # pylint: disable=no-member
    except ConnectTimeout:
        raise EthNodeCommunicationError("Couldn't connect to the ethereum node")

    supported, _ = is_supported_client(node_version)
    if not supported:
        click.secho(
            'You need a Byzantium enabled ethereum node. Parity >= 1.7.6 or Geth >= 1.7.2',
            fg='red',
        )
        sys.exit(1)

    rpc_client = JSONRPCClient(
        web3,
        privatekey_bin,
        gas_price_strategy=gas_price,
    )

    blockchain_service = BlockChainService(privatekey_bin, rpc_client)

    net_id = blockchain_service.network_id
    if net_id != network_id:
        if network_id in ID_TO_NETWORKNAME and net_id in ID_TO_NETWORKNAME:
            click.secho(
                f"The chosen ethereum network '{ID_TO_NETWORKNAME[network_id]}' "
                f"differs from the ethereum client '{ID_TO_NETWORKNAME[net_id]}'. "
                "Please update your settings.",
                fg='red',
            )
        else:
            click.secho(
                f"The chosen ethereum network id '{network_id}' differs from the "
                f"ethereum client '{net_id}'. "
                "Please update your settings.",
                fg='red',
            )
        sys.exit(1)

    config['chain_id'] = network_id

    if network_type == 'main':
        config['network_type'] = NetworkType.MAIN
        # Forcing private rooms to true for the mainnet
        config['transport']['matrix']['private_rooms'] = True
    else:
        config['network_type'] = NetworkType.TEST

    network_type = config['network_type']
    chain_config = {}
    contract_addresses_known = False
    contract_addresses = dict()
    if net_id in ID_TO_NETWORK_CONFIG:
        network_config = ID_TO_NETWORK_CONFIG[net_id]
        not_allowed = (
            NetworkType.TEST not in network_config and
            network_type == NetworkType.TEST
        )
        if not_allowed:
            click.secho(
                'The chosen network {} has no test configuration but a test network type '
                'was given. This is not allowed.'.format(
                    ID_TO_NETWORKNAME[network_id],
                ),
                fg='red',
            )
            sys.exit(1)

        if network_type in network_config:
            chain_config = network_config[network_type]
            contract_addresses = chain_config['contract_addresses']
            contract_addresses_known = True

    if sync_check:
        check_synced(blockchain_service)

    contract_addresses_given = (
        registry_contract_address is not None and
        secret_registry_contract_address is not None and
        discovery_contract_address is not None
    )

    if not contract_addresses_given and not contract_addresses_known:
        click.secho(
            f"There are no known contract addresses for network id '{net_id}'. "
            "Please provide them in the command line or in the configuration file.",
            fg='red',
        )
        sys.exit(1)

    try:
        token_network_registry = blockchain_service.token_network_registry(
            registry_contract_address or contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
        )
    except ContractVersionMismatch:
        handle_contract_version_mismatch('token network registry', registry_contract_address)
    except AddressWithoutCode:
        handle_contract_no_code('token network registry', registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address('token network registry', registry_contract_address)

    try:
        secret_registry = blockchain_service.secret_registry(
            secret_registry_contract_address or contract_addresses[CONTRACT_SECRET_REGISTRY],
        )
    except ContractVersionMismatch:
        handle_contract_version_mismatch('secret registry', secret_registry_contract_address)
    except AddressWithoutCode:
        handle_contract_no_code('secret registry', secret_registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address('secret registry', secret_registry_contract_address)

    database_path = os.path.join(
        datadir,
        f'node_{pex(address)}',
        f'netid_{net_id}',
        f'network_{pex(token_network_registry.address)}',
        f'v{RAIDEN_DB_VERSION}_log.db',
    )
    config['database_path'] = database_path

    print(
        '\nYou are connected to the \'{}\' network and the DB path is: {}'.format(
            ID_TO_NETWORKNAME.get(net_id) or net_id,
            database_path,
        ),
    )

    discovery = None
    if transport == 'udp':
        check_discovery_registration_gas(blockchain_service, address)
        try:
            dicovery_proxy = blockchain_service.discovery(
                discovery_contract_address or contract_addresses[CONTRACT_ENDPOINT_REGISTRY],
            )
            discovery = ContractDiscovery(
                blockchain_service.node_address,
                dicovery_proxy,
            )
        except ContractVersionMismatch:
            handle_contract_version_mismatch('discovery', discovery_contract_address)
        except AddressWithoutCode:
            handle_contract_no_code('discovery', discovery_contract_address)
        except AddressWrongContract:
            handle_contract_wrong_address('discovery', discovery_contract_address)

        throttle_policy = TokenBucket(
            config['transport']['udp']['throttle_capacity'],
            config['transport']['udp']['throttle_fill_rate'],
        )

        transport = UDPTransport(
            discovery,
            mapped_socket.socket,
            throttle_policy,
            config['transport']['udp'],
        )
    elif transport == 'matrix':
        try:
            transport = MatrixTransport(config['transport']['matrix'])
        except RaidenError as ex:
            click.secho(f'FATAL: {ex}', fg='red')
            sys.exit(1)
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    raiden_event_handler = RaidenEventHandler()

    try:
        start_block = chain_config.get(START_QUERY_BLOCK_KEY, 0)
        raiden_app = App(
            config=config,
            chain=blockchain_service,
            query_start_block=start_block,
            default_registry=token_network_registry,
            default_secret_registry=secret_registry,
            transport=transport,
            raiden_event_handler=raiden_event_handler,
            discovery=discovery,
        )
    except RaidenError as e:
        click.secho(f'FATAL: {e}', fg='red')
        sys.exit(1)

    try:
        raiden_app.start()
    except RuntimeError as e:
        click.secho(f'FATAL: {e}', fg='red')
        sys.exit(1)
    except filelock.Timeout:
        name_or_id = ID_TO_NETWORKNAME.get(network_id, network_id)
        click.secho(
            f'FATAL: Another Raiden instance already running for account {address_hex} on '
            f'network id {name_or_id}',
            fg='red',
        )
        sys.exit(1)

    return raiden_app


def prompt_account(address_hex, keystore_path, password_file):
    accmgr = AccountManager(keystore_path)
    if not accmgr.accounts:
        click.secho(
            'No Ethereum accounts found in the provided keystore directory {}. '
            'Please provide a directory containing valid ethereum account '
            'files.'.format(keystore_path),
            fg='red',
        )
        sys.exit(1)

    if not accmgr.address_in_keystore(address_hex):
        # check if an address has been passed
        if address_hex is not None:
            click.secho(
                f"Account '{address_hex}' could not be found on the system. Aborting ...",
                fg='red',
            )
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
            click.secho(
                f'Incorrect password for {address_hex} in file. Aborting ...',
                fg='red',
            )
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
                    click.secho(
                        f'Exhausted passphrase unlock attempts for {address_hex}. Aborting ...',
                        fg='red',
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
        if not self._options['accept_disclaimer']:
            click.confirm('\nHave you read and acknowledge the above disclaimer?', abort=True)

        configure_logging(
            self._options['log_config'],
            log_json=self._options['log_json'],
            log_file=self._options['log_file'],
            disable_debug_logfile=self._options['disable_debug_logfile'],
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
                    click.secho(
                        'ERROR: Address %s:%s is in use. '
                        'Use --listen-address <host:port> to specify port to listen on.' %
                        (listen_host, listen_port),
                        fg='red',
                    )
                    sys.exit(1)
            elif self._options['transport'] == 'matrix':
                self._options['mapped_socket'] = None
                app = self._run_app()
            else:
                # Shouldn't happen
                raise RuntimeError(f"Invalid transport type '{self._options['transport']}'")
            app.stop()
        except (ReplacementTransactionUnderpriced, TransactionAlreadyPending) as e:
            click.secho(
                '{}. Please make sure that this Raiden node is the '
                'only user of the selected account'.format(str(e)),
                fg='red',
            )
            sys.exit(1)

    def _run_app(self):
        from raiden.ui.console import Console
        from raiden.api.python import RaidenAPI

        # this catches exceptions raised when waiting for the stalecheck to complete
        try:
            app_ = run_app(**self._options)
        except (EthNodeCommunicationError, RequestsConnectionError):
            print(ETHEREUM_NODE_COMMUNICATION_ERROR)
            sys.exit(1)

        tasks = [app_.raiden]  # RaidenService takes care of Transport and AlarmTask

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
                click.secho(
                    f'ERROR: API Address {api_host}:{api_port} is in use. '
                    f'Use --api-address <host:port> to specify a different port.',
                    fg='red',
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
            tasks.append(api_server)

        if self._options['console']:
            console = Console(app_)
            console.start()
            tasks.append(console)

        # spawn a greenlet to handle the version checking
        version = get_system_spec()['raiden']
        if version is not None:
            tasks.append(gevent.spawn(check_version, version))

        # spawn a greenlet to handle the gas reserve check
        tasks.append(gevent.spawn(check_gas_reserve, app_.raiden))

        self._startup_hook()

        # wait for interrupt
        event = AsyncResult()

        def sig_set(sig=None, _frame=None):
            event.set(sig)

        gevent.signal(signal.SIGQUIT, sig_set)
        gevent.signal(signal.SIGTERM, sig_set)
        gevent.signal(signal.SIGINT, sig_set)

        # quit if any task exits, successfully or not
        for task in tasks:
            task.link(event)

        try:
            event.get()
            print('Signal received. Shutting down ...')
        except (EthNodeCommunicationError, RequestsConnectionError):
            print(ETHEREUM_NODE_COMMUNICATION_ERROR)
            sys.exit(1)
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
                    f'FATAL: An unexpected exception occured. '
                    f'A traceback has been written to {traceback_file.name}\n'
                    f'{ex}',
                    fg='red',
                )
        finally:
            self._shutdown_hook()

            def stop_task(task):
                try:
                    if isinstance(task, Runnable):
                        task.stop()
                    else:
                        task.kill()
                finally:
                    task.get()  # re-raise

            gevent.joinall(
                [gevent.spawn(stop_task, task) for task in tasks],
                app_.config.get('shutdown_timeout', DEFAULT_SHUTDOWN_TIMEOUT),
                raise_error=True,
            )

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
    from raiden.api.python import RaidenAPI
    from raiden.tests.utils.smoketest import (
        TEST_PARTNER_ADDRESS,
        TEST_DEPOSIT_AMOUNT,
        load_smoketest_config,
        run_smoketests,
        setup_testchain_and_raiden,
    )

    report_file = mktemp(suffix='.log')
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

    result = setup_testchain_and_raiden(
        smoketest_config,
        ctx.parent.params['transport'],
        ctx.parent.params['matrix_server'],
        print_step,
    )
    args = result['args']
    contract_addresses = result['contract_addresses']
    token = result['token']
    ethereum = result['ethereum']
    ethereum_config = result['ethereum_config']

    smoketest_config['transport'] = args['transport']
    for option_ in run.params:
        if option_.name in args.keys():
            args[option_.name] = option_.process_value(ctx, args[option_.name])
        else:
            args[option_.name] = option_.default

    port = next(get_free_port('127.0.0.1', 5001))

    args['api_address'] = 'localhost:' + str(port)

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
            registry_address=contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
            token_address=to_canonical_address(token.contract.address),
            partner_address=to_canonical_address(TEST_PARTNER_ADDRESS),
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
                url=urljoin(args['matrix_server'], '/_matrix/client/versions'),
                method='GET',
                io=DEVNULL,
                timeout=30,
                shell=True,
            ):
                args['extra_config'] = {
                    'transport': {
                        'matrix': {
                            'server_name': 'matrix.local.raiden',
                            'available_servers': [],
                        },
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
        args['extra_config'] = {
            'transport': {
                'matrix': {
                    'server_name': 'matrix.local.raiden',
                    'available_servers': [],
                },
            },
        }
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
