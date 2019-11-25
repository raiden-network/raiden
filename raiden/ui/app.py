import os
import sys
from typing import Any, Callable, Dict, TextIO
from urllib.parse import urlparse

import click
import filelock
import structlog
from eth_utils import to_canonical_address, to_checksum_address
from web3 import HTTPProvider, Web3

from raiden.accounts import AccountManager
from raiden.app import App
from raiden.constants import (
    GENESIS_BLOCK_NUMBER,
    MONITORING_BROADCASTING_ROOM,
    PATH_FINDING_BROADCASTING_ROOM,
    RAIDEN_DB_VERSION,
    Environment,
    EthereumForks,
    GoerliForks,
    KovanForks,
    Networks,
    RinkebyForks,
    RopstenForks,
    RoutingMode,
)
from raiden.exceptions import RaidenError
from raiden.message_handler import MessageHandler
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import EventHandler, PFSFeedbackEventHandler, RaidenEventHandler
from raiden.settings import (
    DEFAULT_HTTP_SERVER_PORT,
    DEFAULT_MATRIX_KNOWN_SERVERS,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
)
from raiden.ui.checks import (
    check_ethereum_client_is_supported,
    check_ethereum_confirmed_block_is_not_pruned,
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
from raiden.ui.startup import setup_contracts_or_exit, setup_environment, setup_proxies_or_exit
from raiden.utils import pex, split_endpoint
from raiden.utils.cli import get_matrix_servers
from raiden.utils.mediation_fees import prepare_mediation_fee_config
from raiden.utils.typing import (
    Address,
    BlockNumber,
    ChainID,
    Endpoint,
    FeeAmount,
    Optional,
    Port,
    PrivateKey,
    ProportionalFeeAmount,
    TokenAddress,
    TokenNetworkRegistryAddress,
    Tuple,
)
from raiden_contracts.constants import (
    CONTRACT_MONITORING_SERVICE,
    CONTRACT_ONE_TO_N,
    ID_TO_NETWORKNAME,
)
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


def _setup_matrix(config: Dict[str, Any], routing_mode: RoutingMode) -> MatrixTransport:
    if config["transport"]["matrix"].get("available_servers") is None:
        # fetch list of known servers from raiden-network/raiden-tranport repo
        available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[config["environment_type"]]
        available_servers = get_matrix_servers(available_servers_url)
        log.debug("Fetching available matrix servers", available_servers=available_servers)
        config["transport"]["matrix"]["available_servers"] = available_servers

    # Add PFS broadcast room when not in privat mode
    if routing_mode != RoutingMode.PRIVATE:
        if PATH_FINDING_BROADCASTING_ROOM not in config["transport"]["matrix"]["broadcast_rooms"]:
            config["transport"]["matrix"]["broadcast_rooms"].append(PATH_FINDING_BROADCASTING_ROOM)

    # Add monitoring service broadcast room if enabled
    if config["services"]["monitoring_enabled"] is True:
        config["transport"]["matrix"]["broadcast_rooms"].append(MONITORING_BROADCASTING_ROOM)

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
        address_hex = to_checksum_address(address)

    if password_file:
        privatekey_bin = unlock_account_with_passwordfile(
            account_manager=account_manager, address_hex=address_hex, password_file=password_file
        )
    else:
        privatekey_bin = unlock_account_with_passwordprompt(
            account_manager=account_manager, address_hex=address_hex
        )

    return to_canonical_address(address_hex), privatekey_bin


def get_smart_contracts_start_at(network_id: ChainID) -> BlockNumber:
    if network_id == Networks.MAINNET:
        smart_contracts_start_at = EthereumForks.CONSTANTINOPLE.value
    elif network_id == Networks.ROPSTEN:
        smart_contracts_start_at = RopstenForks.CONSTANTINOPLE.value
    elif network_id == Networks.KOVAN:
        smart_contracts_start_at = KovanForks.CONSTANTINOPLE.value
    elif network_id == Networks.RINKEBY:
        smart_contracts_start_at = RinkebyForks.CONSTANTINOPLE.value
    elif network_id == Networks.GOERLI:
        smart_contracts_start_at = GoerliForks.CONSTANTINOPLE.value
    else:
        smart_contracts_start_at = GENESIS_BLOCK_NUMBER

    return smart_contracts_start_at


def rpc_normalized_endpoint(eth_rpc_endpoint: str) -> str:
    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)

    if "infura.io" in eth_rpc_endpoint:
        # Infura needs to have the https scheme
        return f"https://{parsed_eth_rpc_endpoint.netloc}{parsed_eth_rpc_endpoint.path}"

    if parsed_eth_rpc_endpoint.scheme:
        return eth_rpc_endpoint

    return f"http://{eth_rpc_endpoint}"


def run_app(
    address: Address,
    keystore_path: str,
    gas_price: Callable,
    eth_rpc_endpoint: str,
    tokennetwork_registry_contract_address: TokenNetworkRegistryAddress,
    one_to_n_contract_address: Address,
    secret_registry_contract_address: Address,
    service_registry_contract_address: Address,
    user_deposit_contract_address: Address,
    monitoring_service_contract_address: Address,
    api_address: Endpoint,
    rpc: bool,
    sync_check: bool,
    console: bool,
    password_file: TextIO,
    web_ui: bool,
    datadir: str,
    transport: str,
    matrix_server: str,
    network_id: ChainID,
    environment_type: Environment,
    unrecoverable_error_should_crash: bool,
    pathfinding_service_address: str,
    pathfinding_max_paths: int,
    enable_monitoring: bool,
    resolver_endpoint: str,
    routing_mode: RoutingMode,
    config: Dict[str, Any],
    flat_fee: Tuple[Tuple[TokenAddress, FeeAmount], ...],
    proportional_fee: Tuple[Tuple[TokenAddress, ProportionalFeeAmount], ...],
    proportional_imbalance_fee: Tuple[Tuple[TokenAddress, ProportionalFeeAmount], ...],
    blockchain_query_interval: float,
    cap_mediation_fees: bool,
    **kwargs: Any,  # FIXME: not used here, but still receives stuff in smoketest
) -> App:
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    token_network_registry_deployed_at: Optional[BlockNumber]
    smart_contracts_start_at: BlockNumber

    if datadir is None:
        datadir = os.path.join(os.path.expanduser("~"), ".raiden")

    account_manager = AccountManager(keystore_path)
    web3 = Web3(HTTPProvider(rpc_normalized_endpoint(eth_rpc_endpoint)))

    check_sql_version()
    check_ethereum_has_accounts(account_manager)
    check_ethereum_client_is_supported(web3)
    check_ethereum_network_id(network_id, web3)

    address, privatekey = get_account_and_private_key(account_manager, address, password_file)

    api_host, api_port = split_endpoint(api_address)

    if not api_port:
        api_port = Port(DEFAULT_HTTP_SERVER_PORT)

    fee_config = prepare_mediation_fee_config(
        cli_token_to_flat_fee=flat_fee,
        cli_token_to_proportional_fee=proportional_fee,
        cli_token_to_proportional_imbalance_fee=proportional_imbalance_fee,
        cli_cap_mediation_fees=cap_mediation_fees,
    )

    config["console"] = console
    config["rpc"] = rpc
    config["web_ui"] = rpc and web_ui
    config["api_host"] = api_host
    config["api_port"] = api_port
    config["resolver_endpoint"] = resolver_endpoint
    config["transport_type"] = transport
    config["transport"]["matrix"]["server"] = matrix_server
    config["unrecoverable_error_should_crash"] = unrecoverable_error_should_crash
    config["services"]["pathfinding_max_paths"] = pathfinding_max_paths
    config["services"]["monitoring_enabled"] = enable_monitoring
    config["chain_id"] = network_id
    config["mediation_fees"] = fee_config
    config["blockchain"]["query_interval"] = blockchain_query_interval

    setup_environment(config, environment_type)

    contracts = setup_contracts_or_exit(config, network_id)

    rpc_client = JSONRPCClient(
        web3=web3,
        privkey=privatekey,
        gas_price_strategy=gas_price,
        block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    )

    token_network_registry_deployed_at = None
    if "TokenNetworkRegistry" in contracts:
        token_network_registry_deployed_at = BlockNumber(
            contracts["TokenNetworkRegistry"]["block_number"]
        )

    if token_network_registry_deployed_at is None:
        smart_contracts_start_at = get_smart_contracts_start_at(network_id)
    else:
        smart_contracts_start_at = token_network_registry_deployed_at

    proxy_manager = ProxyManager(
        rpc_client=rpc_client,
        contract_manager=ContractManager(config["contracts_path"]),
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=token_network_registry_deployed_at,
            filters_start_at=smart_contracts_start_at,
        ),
    )

    if sync_check:
        check_synced(proxy_manager)

    proxies = setup_proxies_or_exit(
        config=config,
        tokennetwork_registry_contract_address=tokennetwork_registry_contract_address,
        secret_registry_contract_address=secret_registry_contract_address,
        user_deposit_contract_address=user_deposit_contract_address,
        service_registry_contract_address=service_registry_contract_address,
        proxy_manager=proxy_manager,
        contracts=contracts,
        routing_mode=routing_mode,
        pathfinding_service_address=pathfinding_service_address,
    )

    check_ethereum_confirmed_block_is_not_pruned(
        jsonrpc_client=rpc_client,
        secret_registry=proxies.secret_registry,
        confirmation_blocks=config["blockchain"]["confirmation_blocks"],
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

    if transport == "matrix":
        matrix_transport = _setup_matrix(config, routing_mode)
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    event_handler: EventHandler = RaidenEventHandler()

    # User should be told how to set fees, if using default fee settings
    log.debug("Fee Settings", fee_settings=fee_config)
    has_default_fees = (
        len(fee_config.token_to_flat_fee) == 0
        and len(fee_config.token_to_proportional_fee) == 0
        and len(fee_config.token_to_proportional_imbalance_fee) == 0
    )
    if has_default_fees:
        click.secho(
            "Default fee settings are used. "
            "If you want use Raiden with mediation fees - flat, proportional and imbalance fees - "
            "see https://raiden-network.readthedocs.io/en/latest/overview_and_guide.html#firing-it-up",  # noqa: E501
            fg="yellow",
        )

    monitoring_contract_required = (
        enable_monitoring and CONTRACT_MONITORING_SERVICE not in contracts
    )
    if monitoring_contract_required:
        click.secho(
            "Monitoring is enabled but the contract for this ethereum network was not found. "
            "Please provide monitoring service contract address using "
            "--monitoring-service-address.",
            fg="red",
        )
        sys.exit(1)

    # Only send feedback when PFS is used
    if routing_mode == RoutingMode.PFS:
        event_handler = PFSFeedbackEventHandler(event_handler)

    message_handler = MessageHandler()

    try:
        raiden_app = App(
            config=config,
            rpc_client=rpc_client,
            proxy_manager=proxy_manager,
            query_start_block=smart_contracts_start_at,
            default_one_to_n_address=(
                one_to_n_contract_address or contracts[CONTRACT_ONE_TO_N]["address"]
            ),
            default_registry=proxies.token_network_registry,
            default_secret_registry=proxies.secret_registry,
            default_service_registry=proxies.service_registry,
            default_msc_address=(
                monitoring_service_contract_address
                or contracts[CONTRACT_MONITORING_SERVICE]["address"]
            ),
            transport=matrix_transport,
            raiden_event_handler=event_handler,
            message_handler=message_handler,
            routing_mode=routing_mode,
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
            f"{to_checksum_address(address)} on network id {name_or_id}",
            fg="red",
        )
        sys.exit(1)

    return raiden_app
