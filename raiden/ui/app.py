import os
import sys
from urllib.parse import urlparse

import click
import filelock
import structlog
from eth_utils import to_canonical_address, to_normalized_address
from web3 import HTTPProvider, Web3

from raiden.accounts import AccountManager
from raiden.constants import MONITORING_BROADCASTING_ROOM, RAIDEN_DB_VERSION, Environment
from raiden.exceptions import (
    AddressWithoutCode,
    AddressWrongContract,
    ContractVersionMismatch,
    RaidenError,
)
from raiden.message_handler import MessageHandler
from raiden.network.blockchain_service import BlockChainService
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import (
    DEFAULT_MATRIX_KNOWN_SERVERS,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
)
from raiden.ui.checks import (
    check_discovery_registration_gas,
    check_ethereum_client_is_supported,
    check_ethereum_has_accounts,
    check_ethereum_network_id,
    check_raiden_environment,
    check_smart_contract_addresses,
    check_sql_version,
    check_synced,
)
from raiden.ui.prompt import (
    prompt_account,
    unlock_account_with_passwordfile,
    unlock_account_with_passwordprompt,
)
from raiden.ui.startup import (
    environment_type_to_contracts_version,
    handle_contract_no_code,
    handle_contract_version_mismatch,
    handle_contract_wrong_address,
    setup_proxies_or_exit,
    setup_udp,
)
from raiden.utils import pex, split_endpoint
from raiden.utils.cli import get_matrix_servers
from raiden.utils.typing import Address, AddressHex, Optional, PrivateKey, TextIO, Tuple
from raiden_contracts.constants import ID_TO_NETWORKNAME
from raiden_contracts.contract_manager import (
    ContractManager,
    contracts_precompiled_path,
    get_contracts_deployment_info,
)

log = structlog.get_logger(__name__)


def get_account_and_private_key(
        account_manager: AccountManager,
        address_hex: Optional[AddressHex],
        password_file: Optional[TextIO],
) -> Tuple[Address, PrivateKey]:
    if not address_hex:
        address_hex = prompt_account(account_manager)
    else:
        address_hex = AddressHex(to_normalized_address(address_hex))

    if password_file:
        privatekey_bin = unlock_account_with_passwordfile(
            account_manager=account_manager,
            address_hex=address_hex,
            password_file=password_file,
        )
    else:
        privatekey_bin = unlock_account_with_passwordprompt(
            account_manager=account_manager,
            address_hex=address_hex,
        )

    return to_canonical_address(address_hex), privatekey_bin


def rpc_normalized_endpoint(eth_rpc_endpoint):
    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)

    if parsed_eth_rpc_endpoint.scheme:
        return eth_rpc_endpoint

    return f'http://{eth_rpc_endpoint}'


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
        pathfinding_eth_address,
        pathfinding_max_paths,
        enable_monitoring,
        resolver_endpoint,
        routing_mode,
        config=None,
        extra_config=None,
        **kwargs,
):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument
    from raiden.app import App

    check_sql_version()
    check_raiden_environment(network_id, environment_type)

    account_manager = AccountManager(keystore_path)
    check_ethereum_has_accounts(account_manager)
    (address, privatekey_bin) = get_account_and_private_key(
        account_manager,
        address,
        password_file,
    )

    web3 = Web3(HTTPProvider(rpc_normalized_endpoint(eth_rpc_endpoint)))
    check_ethereum_client_is_supported(web3)
    check_ethereum_network_id(network_id, web3)

    contracts_version = environment_type_to_contracts_version(environment_type)
    contracts_path = contracts_precompiled_path(contracts_version)
    contract_manager = ContractManager(contracts_path)

    contracts = dict()
    if network_id in ID_TO_NETWORKNAME and ID_TO_NETWORKNAME[network_id] != 'smoketest':
        deployment_data = get_contracts_deployment_info(
            chain_id=network_id,
            version=contracts_version,
        )
        contracts = deployment_data['contracts']
    else:
        check_smart_contract_addresses(
            environment_type,
            network_id,
            tokennetwork_registry_contract_address,
            secret_registry_contract_address,
            endpoint_registry_contract_address,
        )

    rpc_client = JSONRPCClient(
        web3=web3,
        privkey=privatekey_bin,
        gas_price_strategy=gas_price,
        block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
        uses_infura='infura.io' in eth_rpc_endpoint,
    )
    blockchain_service = BlockChainService(
        jsonrpc_client=rpc_client,
        contract_manager=contract_manager,
    )

    if sync_check:
        check_synced(blockchain_service)

    if transport == 'udp':
        check_discovery_registration_gas(blockchain_service, address)

    (api_host, api_port) = split_endpoint(api_address)

    config['console'] = console
    config['rpc'] = rpc
    config['web_ui'] = rpc and web_ui
    config['api_host'] = api_host
    config['api_port'] = api_port
    config['resolver_endpoint'] = resolver_endpoint
    timeout = max_unresponsive_time / DEFAULT_NAT_KEEPALIVE_RETRIES
    config['unrecoverable_error_should_crash'] = unrecoverable_error_should_crash
    config['services']['pathfinding_max_paths'] = pathfinding_max_paths
    config['services']['monitoring_enabled'] = enable_monitoring
    config['chain_id'] = network_id
    config['contracts_path'] = contracts_path
    config['environment_type'] = environment_type

    config['transport_type'] = transport
    if transport == 'udp':
        if not mapped_socket:
            raise RuntimeError('Missing socket')

        (listen_host, listen_port) = split_endpoint(listen_address)
        config['socket'] = mapped_socket.socket
        config['transport']['udp']['host'] = listen_host
        config['transport']['udp']['port'] = listen_port
        config['transport']['udp']['external_ip'] = mapped_socket.external_ip
        config['transport']['udp']['external_port'] = mapped_socket.external_port
        config['transport']['udp']['nat_keepalive_retries'] = DEFAULT_NAT_KEEPALIVE_RETRIES
        config['transport']['udp']['nat_keepalive_timeout'] = timeout

    elif transport == 'matrix':
        config['transport']['matrix']['server'] = matrix_server

        if config['transport']['matrix'].get('available_servers') is None:
            available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[config['environment_type']]
            available_servers = get_matrix_servers(available_servers_url)
            config['transport']['matrix']['available_servers'] = available_servers

        if config['services']['monitoring_enabled'] is True:
            config['transport']['matrix']['global_rooms'].append(MONITORING_BROADCASTING_ROOM)

        # Safe configuration: restrictions for mainnet apply and matrix rooms
        # have to be private
        if environment_type == Environment.PRODUCTION:
            config['transport']['matrix']['private_rooms'] = True

    proxies = setup_proxies_or_exit(
        config=config,
        tokennetwork_registry_contract_address=tokennetwork_registry_contract_address,
        secret_registry_contract_address=secret_registry_contract_address,
        user_deposit_contract_address=user_deposit_contract_address,
        service_registry_contract_address=service_registry_contract_address,
        blockchain_service=blockchain_service,
        contracts=contracts,
        routing_mode=routing_mode,
        pathfinding_service_address=pathfinding_service_address,
        pathfinding_eth_address=pathfinding_eth_address,
    )

    database_path = os.path.join(
        datadir,
        f'node_{pex(address)}',
        f'netid_{network_id}',
        f'network_{pex(proxies.token_network_registry.address)}',
        f'v{RAIDEN_DB_VERSION}_log.db',
    )
    config['database_path'] = database_path

    network_id_or_name = ID_TO_NETWORKNAME.get(network_id, network_id)
    print(
        f'Raiden is running in {environment_type.value.lower()} mode, '
        f'connected to the network {network_id_or_name}. The DB path is '
        f'{database_path}',
    )

    discovery = None
    if transport == 'udp':
        try:
            transport, discovery = setup_udp(
                config,
                blockchain_service,
                address,
                contracts,
                endpoint_registry_contract_address,
            )
        except ContractVersionMismatch as e:
            handle_contract_version_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code('Endpoint Registry', endpoint_registry_contract_address)
        except AddressWrongContract:
            handle_contract_wrong_address('Endpoint Registry', endpoint_registry_contract_address)

    elif transport == 'matrix':
        try:
            transport = MatrixTransport(config['transport']['matrix'])
        except RaidenError as ex:
            click.secho(f'FATAL: {ex}', fg='red')
            sys.exit(1)
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    start_block = 0
    if 'TokenNetworkRegistry' in contracts:
        start_block = contracts['TokenNetworkRegistry']['block_number']

    try:
        raiden_app = App(
            config=config,
            chain=blockchain_service,
            query_start_block=start_block,
            default_registry=proxies.token_network_registry,
            default_secret_registry=proxies.secret_registry,
            default_service_registry=proxies.service_registry,
            transport=transport,
            raiden_event_handler=RaidenEventHandler(),
            message_handler=MessageHandler(),
            discovery=discovery,
            user_deposit=proxies.user_deposit,
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
            f'FATAL: Another Raiden instance already running for account '
            f'{to_normalized_address(address)} on network id {name_or_id}',
            fg='red',
        )
        sys.exit(1)

    return raiden_app
