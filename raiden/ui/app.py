import os
import sys
from typing import Any, Callable, Dict, TextIO
from urllib.parse import urlparse

import click
import filelock
import structlog
from eth_utils import is_address, to_canonical_address
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
    MatrixTransportConfig,
    ServiceConfig,
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
from raiden.ui.startup import (
    load_deployed_contracts_data,
    load_deployment_addresses_from_contracts,
    load_deployment_addresses_from_udc,
    raiden_bundle_from_contracts_deployment,
    services_bundle_from_contracts_deployment,
    setup_environment,
)
from raiden.utils.cli import get_matrix_servers
from raiden.utils.formatting import pex, to_checksum_address
from raiden.utils.http import split_endpoint
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
    Tuple,
    UserDepositAddress,
)
from raiden_contracts.constants import ID_TO_NETWORKNAME
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


def setup_matrix(
    transport_config: MatrixTransportConfig,
    services_config: ServiceConfig,
    environment_type: Environment,
    routing_mode: RoutingMode,
) -> MatrixTransport:
    if not transport_config.available_servers:
        # fetch list of known servers from raiden-network/raiden-tranport repo
        available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[environment_type]
        available_servers = get_matrix_servers(available_servers_url)
        log.debug("Fetching available matrix servers", available_servers=available_servers)
        transport_config.available_servers = available_servers

    # Add PFS broadcast room when not in privat mode
    if routing_mode != RoutingMode.PRIVATE:
        if PATH_FINDING_BROADCASTING_ROOM not in transport_config.broadcast_rooms:
            transport_config.broadcast_rooms.append(PATH_FINDING_BROADCASTING_ROOM)

    # Add monitoring service broadcast room if enabled
    if services_config.monitoring_enabled is True:
        transport_config.broadcast_rooms.append(MONITORING_BROADCASTING_ROOM)

    return MatrixTransport(config=transport_config, environment=environment_type)


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
    user_deposit_contract_address: Optional[UserDepositAddress],
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
    config["transport"].server = matrix_server
    config["unrecoverable_error_should_crash"] = unrecoverable_error_should_crash
    config["services"].pathfinding_max_paths = pathfinding_max_paths
    config["services"].monitoring_enabled = enable_monitoring
    config["chain_id"] = network_id
    config["mediation_fees"] = fee_config
    config["blockchain"]["query_interval"] = blockchain_query_interval

    setup_environment(config, environment_type)

    contracts = load_deployed_contracts_data(config, network_id)

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

    # The user has the option to launch Raiden with a custom
    # user deposit contract address. This can be used to load
    # the addresses for the rest of the deployed contracts.
    # The steps done here make sure that if a UDC address is provided,
    # the address has to be valid and all the connected contracts
    # are configured properly.
    # If a UDC address was not provided, Raiden would fall back
    # to using the ones deployed and provided by the raiden-contracts package.
    if user_deposit_contract_address is not None:
        if not is_address(user_deposit_contract_address):
            click.secho("The user deposit address is invalid", fg="red")
            sys.exit(1)

        deployed_addresses = load_deployment_addresses_from_udc(
            proxy_manager=proxy_manager,
            user_deposit_address=user_deposit_contract_address,
            block_identifier="latest",
        )
    else:
        deployed_addresses = load_deployment_addresses_from_contracts(contracts=contracts)

    raiden_bundle = raiden_bundle_from_contracts_deployment(
        proxy_manager=proxy_manager,
        token_network_registry_address=deployed_addresses.token_network_registry_address,
        secret_registry_address=deployed_addresses.secret_registry_address,
    )

    services_bundle = services_bundle_from_contracts_deployment(
        config=config,
        deployed_addresses=deployed_addresses,
        proxy_manager=proxy_manager,
        routing_mode=routing_mode,
        pathfinding_service_address=pathfinding_service_address,
        enable_monitoring=enable_monitoring,
    )

    check_ethereum_confirmed_block_is_not_pruned(
        jsonrpc_client=rpc_client,
        secret_registry=raiden_bundle.secret_registry,
        confirmation_blocks=config["blockchain"]["confirmation_blocks"],
    )

    database_path = os.path.join(
        datadir,
        f"node_{pex(address)}",
        f"netid_{network_id}",
        f"network_{pex(raiden_bundle.token_network_registry.address)}",
        f"v{RAIDEN_DB_VERSION}_log.db",
    )
    config["database_path"] = database_path

    print(
        "\nYou are connected to the '{}' network and the DB path is: {}".format(
            ID_TO_NETWORKNAME.get(network_id, network_id), database_path
        )
    )

    if transport == "matrix":
        matrix_transport = setup_matrix(
            config["transport"], config["services"], environment_type, routing_mode
        )
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

    # Only send feedback when PFS is used
    if routing_mode == RoutingMode.PFS:
        event_handler = PFSFeedbackEventHandler(event_handler)

    message_handler = MessageHandler()

    one_to_n_address = (
        services_bundle.one_to_n.address if services_bundle.one_to_n is not None else None
    )
    monitoring_service_address = (
        services_bundle.monitoring_service.address
        if services_bundle.monitoring_service is not None
        else None
    )

    try:
        raiden_app = App(
            config=config,
            rpc_client=rpc_client,
            proxy_manager=proxy_manager,
            query_start_block=smart_contracts_start_at,
            default_registry=raiden_bundle.token_network_registry,
            default_secret_registry=raiden_bundle.secret_registry,
            default_one_to_n_address=one_to_n_address,
            default_service_registry=services_bundle.service_registry,
            default_msc_address=monitoring_service_address,
            transport=matrix_transport,
            raiden_event_handler=event_handler,
            message_handler=message_handler,
            routing_mode=routing_mode,
            user_deposit=services_bundle.user_deposit,
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
