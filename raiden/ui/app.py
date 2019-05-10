import os
import sys
from typing import Any, Callable, Dict, TextIO
from urllib.parse import urlparse

import click
import filelock
import structlog
from eth_utils import to_canonical_address, to_normalized_address
from web3 import HTTPProvider, Web3

from raiden.accounts import AccountManager
from raiden.constants import (
    MONITORING_BROADCASTING_ROOM,
    PATH_FINDING_BROADCASTING_ROOM,
    RAIDEN_DB_VERSION,
    Environment,
    RoutingMode,
)
from raiden.exceptions import RaidenError
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
    check_ethereum_client_is_supported,
    check_ethereum_has_accounts,
    check_ethereum_network_id,
    check_sql_version,
    check_synced,
)
from raiden.ui.prompt import (
    prompt_account,
    unlock_account_with_passwordfile,
    unlock_account_with_passwordprompt,
)
from raiden.ui.startup import (
    setup_contracts_or_exit,
    setup_environment,
    setup_proxies_or_exit,
    setup_udp_or_exit,
)
from raiden.utils import BlockNumber, pex, split_endpoint
from raiden.utils.cli import get_matrix_servers
from raiden.utils.typing import Address, Optional, PrivateKey, Tuple
from raiden_contracts.constants import ID_TO_NETWORKNAME
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


def _setup_matrix(config):
    if config["transport"]["matrix"].get("available_servers") is None:
        # fetch list of known servers from raiden-network/raiden-tranport repo
        available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[config["environment_type"]]
        available_servers = get_matrix_servers(available_servers_url)
        log.debug("Fetching available matrix servers", available_servers=available_servers)
        config["transport"]["matrix"]["available_servers"] = available_servers

    # TODO: This needs to be adjusted once #3735 gets implemented
    # Add PFS broadcast room if enabled
    if config["services"]["pathfinding_service_address"] is not None:
        if PATH_FINDING_BROADCASTING_ROOM not in config["transport"]["matrix"]["global_rooms"]:
            config["transport"]["matrix"]["global_rooms"].append(PATH_FINDING_BROADCASTING_ROOM)

    # Add monitoring service broadcast room if enabled
    if config["services"]["monitoring_enabled"] is True:
        config["transport"]["matrix"]["global_rooms"].append(MONITORING_BROADCASTING_ROOM)

    try:
        transport = MatrixTransport(config["transport"]["matrix"])
    except RaidenError as ex:
        click.secho(f"FATAL: {ex}", fg="red")
        sys.exit(1)

    return transport


def get_account_and_private_key(
    account_manager: AccountManager, address: Optional[Address], password_file: Optional[TextIO]
) -> Tuple[Address, PrivateKey]:
    if not address:
        address_hex = prompt_account(account_manager)
    else:
        address_hex = to_normalized_address(address)

    if password_file:
        privatekey_bin = unlock_account_with_passwordfile(
            account_manager=account_manager, address_hex=address_hex, password_file=password_file
        )
    else:
        privatekey_bin = unlock_account_with_passwordprompt(
            account_manager=account_manager, address_hex=address_hex
        )

    return to_canonical_address(address_hex), privatekey_bin


def rpc_normalized_endpoint(eth_rpc_endpoint: str) -> str:
    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)

    if parsed_eth_rpc_endpoint.scheme:
        return eth_rpc_endpoint

    return f"http://{eth_rpc_endpoint}"


def run_app(
    address: Address,
    keystore_path: str,
    gas_price: Callable,
    eth_rpc_endpoint: str,
    tokennetwork_registry_contract_address: Address,
    one_to_n_contract_address: Address,
    secret_registry_contract_address: Address,
    service_registry_contract_address: Address,
    endpoint_registry_contract_address: Address,
    user_deposit_contract_address: Address,
    listen_address: str,
    mapped_socket,
    max_unresponsive_time: int,
    api_address: str,
    rpc: bool,
    sync_check: bool,
    console: bool,
    password_file: TextIO,
    web_ui: bool,
    datadir: str,
    transport: str,
    matrix_server: str,
    network_id: int,
    environment_type: Environment,
    unrecoverable_error_should_crash: bool,
    pathfinding_service_address: str,
    pathfinding_max_paths: int,
    enable_monitoring: bool,
    resolver_endpoint: str,
    routing_mode: RoutingMode,
    config: Dict[str, Any],
    **kwargs: Any,  # FIXME: not used here, but still receives stuff in smoketest
):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    from raiden.app import App

    if transport == "udp" and not mapped_socket:
        raise RuntimeError("Missing socket")

    if datadir is None:
        datadir = os.path.join(os.path.expanduser("~"), ".raiden")

    account_manager = AccountManager(keystore_path)
    web3 = Web3(HTTPProvider(rpc_normalized_endpoint(eth_rpc_endpoint)))

    check_sql_version()
    check_ethereum_has_accounts(account_manager)
    check_ethereum_client_is_supported(web3)
    check_ethereum_network_id(network_id, web3)

    (address, privatekey_bin) = get_account_and_private_key(
        account_manager, address, password_file
    )

    (listen_host, listen_port) = split_endpoint(listen_address)
    (api_host, api_port) = split_endpoint(api_address)

    config["transport"]["udp"]["host"] = listen_host
    config["transport"]["udp"]["port"] = listen_port
    config["console"] = console
    config["rpc"] = rpc
    config["web_ui"] = rpc and web_ui
    config["api_host"] = api_host
    config["api_port"] = api_port
    config["resolver_endpoint"] = resolver_endpoint
    if mapped_socket:
        config["socket"] = mapped_socket.socket
        config["transport"]["udp"]["external_ip"] = mapped_socket.external_ip
        config["transport"]["udp"]["external_port"] = mapped_socket.external_port
    config["transport_type"] = transport
    config["transport"]["matrix"]["server"] = matrix_server
    config["transport"]["udp"]["nat_keepalive_retries"] = DEFAULT_NAT_KEEPALIVE_RETRIES
    timeout = max_unresponsive_time / DEFAULT_NAT_KEEPALIVE_RETRIES
    config["transport"]["udp"]["nat_keepalive_timeout"] = timeout
    config["unrecoverable_error_should_crash"] = unrecoverable_error_should_crash
    config["services"]["pathfinding_max_paths"] = pathfinding_max_paths
    config["services"]["monitoring_enabled"] = enable_monitoring
    config["chain_id"] = network_id

    setup_environment(config, environment_type)

    contracts = setup_contracts_or_exit(config, network_id)

    rpc_client = JSONRPCClient(
        web3,
        privatekey_bin,
        gas_price_strategy=gas_price,
        block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
        uses_infura="infura.io" in eth_rpc_endpoint,
    )

    blockchain_service = BlockChainService(
        jsonrpc_client=rpc_client, contract_manager=ContractManager(config["contracts_path"])
    )

    if sync_check:
        check_synced(blockchain_service)

    proxies = setup_proxies_or_exit(
        config=config,
        tokennetwork_registry_contract_address=tokennetwork_registry_contract_address,
        secret_registry_contract_address=secret_registry_contract_address,
        endpoint_registry_contract_address=endpoint_registry_contract_address,
        user_deposit_contract_address=user_deposit_contract_address,
        service_registry_contract_address=service_registry_contract_address,
        blockchain_service=blockchain_service,
        contracts=contracts,
        routing_mode=routing_mode,
        pathfinding_service_address=pathfinding_service_address,
    )

    database_path = os.path.join(
        datadir,
        f"node_{pex(address)}",
        f"netid_{network_id}",
        f"network_{pex(proxies.token_network_registry.address)}",
        f"v{RAIDEN_DB_VERSION}_log.db",
    )
    config["database_path"] = database_path

    print(
        "\nYou are connected to the '{}' network and the DB path is: {}".format(
            ID_TO_NETWORKNAME.get(network_id, network_id), database_path
        )
    )

    discovery = None
    if transport == "udp":
        transport, discovery = setup_udp_or_exit(
            config, blockchain_service, address, contracts, endpoint_registry_contract_address
        )
    elif transport == "matrix":
        transport = _setup_matrix(config)
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    raiden_event_handler = RaidenEventHandler()

    message_handler = MessageHandler()

    try:
        start_block = 0
        if "TokenNetworkRegistry" in contracts:
            start_block = contracts["TokenNetworkRegistry"]["block_number"]

        raiden_app = App(
            config=config,
            chain=blockchain_service,
            query_start_block=BlockNumber(start_block),
            default_one_to_n_address=one_to_n_contract_address,
            default_registry=proxies.token_network_registry,
            default_secret_registry=proxies.secret_registry,
            default_service_registry=proxies.service_registry,
            transport=transport,
            raiden_event_handler=raiden_event_handler,
            message_handler=message_handler,
            discovery=discovery,
            user_deposit=proxies.user_deposit,
        )
    except RaidenError as e:
        click.secho(f"FATAL: {e}", fg="red")
        sys.exit(1)

    try:
        raiden_app.start()
    except RuntimeError as e:
        click.secho(f"FATAL: {e}", fg="red")
        sys.exit(1)
    except filelock.Timeout:
        name_or_id = ID_TO_NETWORKNAME.get(network_id, network_id)
        click.secho(
            f"FATAL: Another Raiden instance already running for account "
            f"{to_normalized_address(address)} on network id {name_or_id}",
            fg="red",
        )
        sys.exit(1)

    return raiden_app
