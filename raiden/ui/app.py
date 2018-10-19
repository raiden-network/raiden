import os
import sys
from urllib.parse import urlparse

import click
import filelock
import structlog
from eth_utils import encode_hex, to_canonical_address, to_checksum_address, to_normalized_address
from requests.exceptions import ConnectTimeout
from web3 import HTTPProvider, Web3

from raiden.constants import SQLITE_MIN_REQUIRED_VERSION, Environment
from raiden.exceptions import (
    AddressWithoutCode,
    AddressWrongContract,
    ContractVersionMismatch,
    EthNodeCommunicationError,
    RaidenError,
)
from raiden.message_handler import MessageHandler
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.throttle import TokenBucket
from raiden.network.transport import MatrixTransport, UDPTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import (
    DEFAULT_MATRIX_KNOWN_SERVERS,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
)
from raiden.storage.sqlite import RAIDEN_DB_VERSION, assert_sqlite_version
from raiden.utils import is_supported_client, pex, split_endpoint, typing
from raiden.utils.cli import get_matrix_servers
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    ID_TO_NETWORKNAME,
)
from raiden_contracts.contract_manager import (
    ContractManager,
    contracts_precompiled_path,
    get_contracts_deployed,
)

from .prompt import prompt_account
from .sync import check_discovery_registration_gas, check_synced

log = structlog.get_logger(__name__)


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


def _assert_sql_version():
    if not assert_sqlite_version():
        log.error('SQLite3 should be at least version {}'.format(
            '{}.{}.{}'.format(*SQLITE_MIN_REQUIRED_VERSION),
        ))
        sys.exit(1)


def _setup_web3(eth_rpc_endpoint):
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
    return web3


def _setup_udp(
        config,
        blockchain_service,
        address,
        contracts,
        discovery_contract_address,
):
    check_discovery_registration_gas(blockchain_service, address)
    try:
        dicovery_proxy = blockchain_service.discovery(
            discovery_contract_address or to_canonical_address(
                contracts[CONTRACT_ENDPOINT_REGISTRY]['address'],
            ),
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
        address,
        discovery,
        config['socket'],
        throttle_policy,
        config['transport']['udp'],
    )

    return transport, discovery


def _setup_matrix(config):
    if config['transport']['matrix'].get('available_servers') is None:
        # fetch list of known servers from raiden-network/raiden-tranport repo
        available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[config['environment_type']]
        available_servers = get_matrix_servers(available_servers_url)
        config['transport']['matrix']['available_servers'] = available_servers

    try:
        transport = MatrixTransport(config['transport']['matrix'])
    except RaidenError as ex:
        click.secho(f'FATAL: {ex}', fg='red')
        sys.exit(1)

    return transport


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
        environment_type,
        config=None,
        extra_config=None,
        **kwargs,
):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    from raiden.app import App

    _assert_sql_version()

    if transport == 'udp' and not mapped_socket:
        raise RuntimeError('Missing socket')

    if datadir is None:
        datadir = os.path.join(os.path.expanduser('~'), '.raiden')

    address_hex = to_normalized_address(address) if address else None
    address_hex, privatekey_bin = prompt_account(address_hex, keystore_path, password_file)
    address = to_canonical_address(address_hex)

    (listen_host, listen_port) = split_endpoint(listen_address)
    (api_host, api_port) = split_endpoint(api_address)

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
    config['privatekey_hex'] = encode_hex(privatekey_bin)

    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)
    if not parsed_eth_rpc_endpoint.scheme:
        eth_rpc_endpoint = f'http://{eth_rpc_endpoint}'

    web3 = _setup_web3(eth_rpc_endpoint)

    rpc_client = JSONRPCClient(
        web3,
        privatekey_bin,
        gas_price_strategy=gas_price,
        block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    )

    blockchain_service = BlockChainService(
        privatekey_bin=privatekey_bin,
        jsonrpc_client=rpc_client,
        # Not giving the contract manager here, but injecting it later
        # since we first need blockchain service to calculate the network id
    )

    given_network_id = network_id
    node_network_id = blockchain_service.network_id
    known_given_network_id = given_network_id in ID_TO_NETWORKNAME
    known_node_network_id = node_network_id in ID_TO_NETWORKNAME

    if node_network_id != given_network_id:
        if known_given_network_id and known_node_network_id:
            click.secho(
                f"The chosen ethereum network '{ID_TO_NETWORKNAME[given_network_id]}' "
                f"differs from the ethereum client '{ID_TO_NETWORKNAME[node_network_id]}'. "
                "Please update your settings.",
                fg='red',
            )
        else:
            click.secho(
                f"The chosen ethereum network id '{given_network_id}' differs "
                f"from the ethereum client '{node_network_id}'. "
                "Please update your settings.",
                fg='red',
            )
        sys.exit(1)

    config['chain_id'] = given_network_id

    log.debug('Environment setting', type=environment_type)
    if environment_type == Environment.PRODUCTION:
        # Safe configuration: restrictions for mainnet apply and matrix rooms have to be private
        config['environment_type'] = Environment.PRODUCTION
        config['transport']['matrix']['private_rooms'] = True
    else:
        config['environment_type'] = Environment.PRODUCTION

    environment_type = config['environment_type']
    chain_config = {}
    contract_addresses_known = False
    contracts = dict()
    config['contracts_path'] = contracts_precompiled_path()
    if node_network_id in ID_TO_NETWORKNAME and ID_TO_NETWORKNAME[node_network_id] != 'smoketest':
        contracts_version = 'pre_limits' if environment_type == Environment.DEVELOPMENT else None
        deployment_data = get_contracts_deployed(node_network_id, contracts_version)
        config['contracts_path'] = contracts_precompiled_path(contracts_version)
        not_allowed = (  # for now we only disallow mainnet with test configuration
            network_id == 1 and
            environment_type == Environment.DEVELOPMENT
        )
        if not_allowed:
            click.secho(
                f'The chosen network ({ID_TO_NETWORKNAME[node_network_id]}) is not a testnet, '
                'but the "development" environment was selected.\n'
                'This is not allowed. Please start again with a safe environment setting '
                '(--environment production).',
                fg='red',
            )
            sys.exit(1)

        contracts = deployment_data['contracts']
        contract_addresses_known = True

    blockchain_service.inject_contract_manager(ContractManager(config['contracts_path']))

    if sync_check:
        check_synced(blockchain_service, known_node_network_id)

    contract_addresses_given = (
        registry_contract_address is not None and
        secret_registry_contract_address is not None and
        discovery_contract_address is not None
    )

    if not contract_addresses_given and not contract_addresses_known:
        click.secho(
            f"There are no known contract addresses for network id '{given_network_id}'. "
            "Please provide them on the command line or in the configuration file.",
            fg='red',
        )
        sys.exit(1)

    try:
        token_network_registry = blockchain_service.token_network_registry(
            registry_contract_address or to_canonical_address(
                contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]['address'],
            ),
        )
    except ContractVersionMismatch:
        handle_contract_version_mismatch('token network registry', registry_contract_address)
    except AddressWithoutCode:
        handle_contract_no_code('token network registry', registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address('token network registry', registry_contract_address)

    try:
        secret_registry = blockchain_service.secret_registry(
            secret_registry_contract_address or to_canonical_address(
                contracts[CONTRACT_SECRET_REGISTRY]['address'],
            ),
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
        f'netid_{given_network_id}',
        f'network_{pex(token_network_registry.address)}',
        f'v{RAIDEN_DB_VERSION}_log.db',
    )
    config['database_path'] = database_path

    print(
        '\nYou are connected to the \'{}\' network and the DB path is: {}'.format(
            ID_TO_NETWORKNAME.get(given_network_id, given_network_id),
            database_path,
        ),
    )

    discovery = None
    if transport == 'udp':
        transport, discovery = _setup_udp(
            config,
            blockchain_service,
            address,
            contracts,
            discovery_contract_address,
        )
    elif transport == 'matrix':
        transport = _setup_matrix(config)
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    raiden_event_handler = RaidenEventHandler()
    message_handler = MessageHandler()

    try:
        if 'contracts' in chain_config:
            start_block = chain_config['contracts']['TokenNetworkRegistry']['block_number']
        else:
            start_block = 0

        raiden_app = App(
            config=config,
            chain=blockchain_service,
            query_start_block=start_block,
            default_registry=token_network_registry,
            default_secret_registry=secret_registry,
            transport=transport,
            raiden_event_handler=raiden_event_handler,
            message_handler=message_handler,
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
        name_or_id = ID_TO_NETWORKNAME.get(given_network_id, given_network_id)
        click.secho(
            f'FATAL: Another Raiden instance already running for account {address_hex} on '
            f'network id {name_or_id}',
            fg='red',
        )
        sys.exit(1)

    return raiden_app
