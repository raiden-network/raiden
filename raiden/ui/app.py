import os
import sys
from urllib.parse import urlparse

import click
import filelock
import structlog
from eth_utils import to_canonical_address, to_checksum_address, to_normalized_address
from requests.exceptions import ConnectTimeout
from web3 import HTTPProvider, Web3

from raiden.constants import (
    MONITORING_BROADCASTING_ROOM,
    RAIDEN_DB_VERSION,
    SQLITE_MIN_REQUIRED_VERSION,
    Environment,
    RoutingMode,
)
from raiden.exceptions import (
    AddressWithoutCode,
    AddressWrongContract,
    ContractVersionMismatch,
    EthNodeCommunicationError,
    EthNodeInterfaceError,
    RaidenError,
)
from raiden.message_handler import MessageHandler
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.pathfinding import configure_pfs
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.throttle import TokenBucket
from raiden.network.transport import MatrixTransport, UDPTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import (
    DEFAULT_MATRIX_KNOWN_SERVERS,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    DEVELOPMENT_CONTRACT_VERSION,
    RED_EYES_CONTRACT_VERSION,
)
from raiden.storage.sqlite import assert_sqlite_version
from raiden.utils import is_supported_client, pex, split_endpoint, typing
from raiden.utils.cli import get_matrix_servers
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    CONTRACT_USER_DEPOSIT,
    ID_TO_NETWORKNAME,
)
from raiden_contracts.contract_manager import (
    ContractManager,
    contracts_precompiled_path,
    get_contracts_deployment_info,
)

from .prompt import prompt_account
from .sync import check_discovery_registration_gas, check_synced

log = structlog.get_logger(__name__)


def handle_contract_version_mismatch(mismatch_exception: ContractVersionMismatch) -> None:
    click.secho(
        f'{str(mismatch_exception)}. Please update your Raiden installation.',
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
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying ethereum node does not have the web3 rpc interface '
            'enabled. Please run it with --rpcapi eth,net,web3,txpool for geth '
            'and --jsonrpc-apis=eth,net,web3,parity for parity.',
        )

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
        endpoint_registry_contract_address,
):
    check_discovery_registration_gas(blockchain_service, address)
    try:
        dicovery_proxy = blockchain_service.discovery(
            endpoint_registry_contract_address or to_canonical_address(
                contracts[CONTRACT_ENDPOINT_REGISTRY]['address'],
            ),
        )
        discovery = ContractDiscovery(
            blockchain_service.node_address,
            dicovery_proxy,
        )
    except ContractVersionMismatch as e:
        handle_contract_version_mismatch(e)
    except AddressWithoutCode:
        handle_contract_no_code('Endpoint Registry', endpoint_registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address('Endpoint Registry', endpoint_registry_contract_address)

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
        log.debug('Fetching available matrix servers', available_servers=available_servers)
        config['transport']['matrix']['available_servers'] = available_servers

    # Add monitoring service broadcast room if enabled
    if config['services']['monitoring_enabled'] is True:
        config['transport']['matrix']['global_rooms'].append(MONITORING_BROADCASTING_ROOM)

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
        tokennetwork_registry_contract_address,
        secret_registry_contract_address,
        service_registry_contract_address,
        endpoint_registry_contract_address,
        user_deposit_contract_address,
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
        unrecoverable_error_should_crash,
        pathfinding_service_address,
        pathfinding_max_paths,
        enable_monitoring,
        routing_mode,
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
    config['unrecoverable_error_should_crash'] = unrecoverable_error_should_crash
    config['services']['pathfinding_max_paths'] = pathfinding_max_paths
    config['services']['monitoring_enabled'] = enable_monitoring

    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)
    if not parsed_eth_rpc_endpoint.scheme:
        eth_rpc_endpoint = f'http://{eth_rpc_endpoint}'

    web3 = _setup_web3(eth_rpc_endpoint)
    given_network_id = network_id
    node_network_id = int(web3.version.network)  # pylint: disable=no-member
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

    # interpret the provided string argument
    if environment_type == Environment.PRODUCTION:
        # Safe configuration: restrictions for mainnet apply and matrix rooms have to be private
        config['environment_type'] = Environment.PRODUCTION
        config['transport']['matrix']['private_rooms'] = True
    else:
        config['environment_type'] = Environment.DEVELOPMENT

    environment_type = config['environment_type']
    print(f'Raiden is running in {environment_type.value.lower()} mode')

    chain_config = {}
    contract_addresses_known = False
    contracts = dict()
    services_contracts = dict()

    if environment_type == Environment.DEVELOPMENT:
        contracts_version = DEVELOPMENT_CONTRACT_VERSION
    else:
        contracts_version = RED_EYES_CONTRACT_VERSION

    config['contracts_path'] = contracts_precompiled_path(contracts_version)

    if node_network_id in ID_TO_NETWORKNAME and ID_TO_NETWORKNAME[node_network_id] != 'smoketest':
        deployment_data = get_contracts_deployment_info(
            chain_id=node_network_id,
            version=contracts_version,
        )
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

    rpc_client = JSONRPCClient(
        web3,
        privatekey_bin,
        gas_price_strategy=gas_price,
        block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
        uses_infura='infura.io' in eth_rpc_endpoint,
    )

    blockchain_service = BlockChainService(
        jsonrpc_client=rpc_client,
        contract_manager=ContractManager(config['contracts_path']),
    )

    if sync_check:
        check_synced(blockchain_service, known_node_network_id)

    contract_addresses_given = (
        tokennetwork_registry_contract_address is not None and
        secret_registry_contract_address is not None and
        endpoint_registry_contract_address is not None
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
            tokennetwork_registry_contract_address or to_canonical_address(
                contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]['address'],
            ),
        )
    except ContractVersionMismatch as e:
        handle_contract_version_mismatch(e)
    except AddressWithoutCode:
        handle_contract_no_code('token network registry', tokennetwork_registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address(
            'token network registry',
            tokennetwork_registry_contract_address,
        )

    try:
        secret_registry = blockchain_service.secret_registry(
            secret_registry_contract_address or to_canonical_address(
                contracts[CONTRACT_SECRET_REGISTRY]['address'],
            ),
        )
    except ContractVersionMismatch as e:
        handle_contract_version_mismatch(e)
    except AddressWithoutCode:
        handle_contract_no_code('secret registry', secret_registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address('secret registry', secret_registry_contract_address)

    # If services contracts are provided via the CLI use them instead
    if user_deposit_contract_address is not None:
        services_contracts[CONTRACT_USER_DEPOSIT] = user_deposit_contract_address
    if service_registry_contract_address is not None:
        services_contracts[CONTRACT_SERVICE_REGISTRY] = (
            service_registry_contract_address
        )

    user_deposit = None
    should_use_user_deposit = (
        environment_type == Environment.DEVELOPMENT and
        ID_TO_NETWORKNAME.get(node_network_id) != 'smoketest' and
        CONTRACT_USER_DEPOSIT in services_contracts
    )
    if should_use_user_deposit:
        try:
            user_deposit = blockchain_service.user_deposit(
                user_deposit_contract_address or to_canonical_address(
                    contracts[CONTRACT_USER_DEPOSIT]['address'],
                ),
            )
        except ContractVersionMismatch as e:
            handle_contract_version_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code('user deposit', user_deposit_contract_address)
        except AddressWrongContract:
            handle_contract_wrong_address('user_deposit', user_deposit_contract_address)

    service_registry = None
    if routing_mode == RoutingMode.PFS:

        if environment_type == Environment.PRODUCTION:
            click.secho(
                'Requested production mode and PFS routing mode. This is not supported',
                fg='red',
            )
            sys.exit(1)

        if CONTRACT_SERVICE_REGISTRY not in services_contracts:
            click.secho(
                'Requested PFS routing mode but no service registry is provided. Please'
                'provide it via the --service-registry-contract-address argument',
                fg='red',
            )
            sys.exit(1)

        try:
            service_registry = blockchain_service.service_registry(
                service_registry_contract_address or to_canonical_address(
                    contracts[CONTRACT_SERVICE_REGISTRY]['address'],
                ),
            )
        except ContractVersionMismatch as e:
            handle_contract_version_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code('service registry', service_registry_contract_address)
        except AddressWrongContract:
            handle_contract_wrong_address('secret registry', service_registry_contract_address)

        config['services']['pathfinding_service_address'] = configure_pfs(
            pfs_address=pathfinding_service_address,
            routing_mode=routing_mode,
            service_registry=service_registry,
        )
    else:
        config['services']['pathfinding_service_address'] = None

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
            endpoint_registry_contract_address,
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
            default_service_registry=service_registry,
            transport=transport,
            raiden_event_handler=raiden_event_handler,
            message_handler=message_handler,
            discovery=discovery,
            user_deposit=user_deposit,
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
