import os
from pathlib import Path
from typing import Any, Callable, TextIO
from urllib.parse import urlparse

import click
import structlog
from eth_typing import URI
from eth_utils import is_address, to_canonical_address
from web3 import HTTPProvider, Web3

from raiden.accounts import AccountManager
from raiden.api.rest import APIServer, RestAPI
from raiden.constants import (
    BLOCK_ID_LATEST,
    CHAIN_TO_MIN_REVEAL_TIMEOUT,
    DOC_URL,
    GENESIS_BLOCK_NUMBER,
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
from raiden.exceptions import ConfigurationError, RaidenError
from raiden.message_handler import MessageHandler
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import EventHandler, PFSFeedbackEventHandler, RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_HTTP_SERVER_PORT,
    DEFAULT_MATRIX_KNOWN_SERVERS,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    MATRIX_AUTO_SELECT_SERVER,
    MatrixTransportConfig,
    PythonApiConfig,
    RaidenConfig,
    RestApiConfig,
)
from raiden.ui.checks import (
    check_ethereum_chain_id,
    check_ethereum_confirmed_block_is_not_pruned,
    check_ethereum_has_accounts,
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
)
from raiden.utils.cli import get_matrix_servers
from raiden.utils.formatting import pex, to_checksum_address
from raiden.utils.http import split_endpoint
from raiden.utils.mediation_fees import prepare_mediation_fee_config
from raiden.utils.typing import (
    Address,
    BlockNumber,
    BlockTimeout,
    ChainID,
    Endpoint,
    FeeAmount,
    Optional,
    PrivateKey,
    ProportionalFeeAmount,
    TokenAddress,
    Tuple,
    UserDepositAddress,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK_REGISTRY, ID_TO_CHAINNAME
from raiden_contracts.contract_manager import ContractDevEnvironment, ContractManager

log = structlog.get_logger(__name__)


def fetch_available_matrix_servers(
    transport_config: MatrixTransportConfig, environment_type: Environment
) -> None:
    """
    Fetches the list of known servers from raiden-network/raiden-tranport repo
    for the given environment.
    """
    available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[environment_type]

    log.debug("Fetching available matrix servers")
    available_servers = get_matrix_servers(available_servers_url)
    log.debug("Available matrix servers", available_servers=available_servers)

    transport_config.available_servers = available_servers


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


def get_smart_contracts_start_at(chain_id: ChainID) -> BlockNumber:
    if chain_id == Networks.MAINNET.value:
        smart_contracts_start_at = EthereumForks.CONSTANTINOPLE.value
    elif chain_id == Networks.ROPSTEN.value:
        smart_contracts_start_at = RopstenForks.CONSTANTINOPLE.value
    elif chain_id == Networks.KOVAN.value:
        smart_contracts_start_at = KovanForks.CONSTANTINOPLE.value
    elif chain_id == Networks.RINKEBY.value:
        smart_contracts_start_at = RinkebyForks.CONSTANTINOPLE.value
    elif chain_id == Networks.GOERLI.value:
        smart_contracts_start_at = GoerliForks.CONSTANTINOPLE.value
    else:
        smart_contracts_start_at = GENESIS_BLOCK_NUMBER

    return smart_contracts_start_at


def get_min_reveal_timeout(chain_id: ChainID) -> BlockTimeout:
    return CHAIN_TO_MIN_REVEAL_TIMEOUT.get(chain_id, BlockTimeout(1))


def rpc_normalized_endpoint(eth_rpc_endpoint: str) -> URI:
    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)

    if "infura.io" in eth_rpc_endpoint:
        # Infura needs to have the https scheme
        return URI(f"https://{parsed_eth_rpc_endpoint.netloc}{parsed_eth_rpc_endpoint.path}")

    if parsed_eth_rpc_endpoint.scheme:
        return URI(eth_rpc_endpoint)

    scheme = "http://"
    if eth_rpc_endpoint.startswith("//"):
        scheme = "http:"

    return URI(f"{scheme}{eth_rpc_endpoint}")


def start_api_server(
    rpc_client: JSONRPCClient,
    config: RestApiConfig,
    eth_rpc_endpoint: str,
) -> APIServer:
    api = RestAPI(rpc_client=rpc_client)
    api_server = APIServer(
        rest_api=api,
        config=config,
        eth_rpc_endpoint=eth_rpc_endpoint,
    )
    api_server.start()

    url = f"http://{config.host}:{config.port}/"
    print(
        f"The Raiden API RPC server is now running at {url}.\n\n"
        f"See the Raiden documentation for all available endpoints at\n"
        f"{DOC_URL}"
    )

    return api_server


def setup_raiden_config(
    eth_rpc_endpoint: str,
    api_address: Endpoint,
    rpc: bool,
    rpccorsdomain: str,
    console: bool,
    web_ui: bool,
    matrix_server: str,
    chain_id: ChainID,
    environment_type: Environment,
    development_environment: ContractDevEnvironment,
    unrecoverable_error_should_crash: bool,
    pathfinding_max_paths: int,
    enable_monitoring: bool,
    resolver_endpoint: str,
    default_reveal_timeout: BlockTimeout,
    default_settle_timeout: BlockTimeout,
    flat_fee: Tuple[Tuple[TokenAddress, FeeAmount], ...],
    proportional_fee: Tuple[Tuple[TokenAddress, ProportionalFeeAmount], ...],
    proportional_imbalance_fee: Tuple[Tuple[TokenAddress, ProportionalFeeAmount], ...],
    blockchain_query_interval: float,
    cap_mediation_fees: bool,
    enable_tracing: bool,
    **kwargs: Any,
) -> RaidenConfig:
    """
    Initialise the nested raiden config objects from "flat" arguments.
    Static checking for a sane config should be done here (but no I/O or checks for
    valid environment).
    """
    # pylint: disable=unused-argument

    api_host, api_port = split_endpoint(api_address)

    if not api_port:
        api_port = DEFAULT_HTTP_SERVER_PORT

    domain_list = []
    if rpccorsdomain:
        if "," in rpccorsdomain:
            for domain in rpccorsdomain.split(","):
                domain_list.append(str(domain))
        else:
            domain_list.append(str(rpccorsdomain))

    fee_config = prepare_mediation_fee_config(
        cli_token_to_flat_fee=flat_fee,
        cli_token_to_proportional_fee=proportional_fee,
        cli_token_to_proportional_imbalance_fee=proportional_imbalance_fee,
        cli_cap_mediation_fees=cap_mediation_fees,
    )

    rest_api_config = RestApiConfig(
        rest_api_enabled=rpc,
        web_ui_enabled=rpc and web_ui,
        cors_domain_list=domain_list,
        eth_rpc_endpoint=eth_rpc_endpoint,
        host=api_host,
        port=api_port,
        enable_tracing=enable_tracing,
    )

    minimum_reveal_timeout = get_min_reveal_timeout(chain_id)
    python_api_config = PythonApiConfig(minimum_reveal_timeout=minimum_reveal_timeout)

    if default_reveal_timeout < minimum_reveal_timeout:
        network = Networks(chain_id)
        raise ConfigurationError(
            f"Option `default-reveal-timeout={default_reveal_timeout}` can't be smaller than "
            f"the minimally recommended reveal timeout ({minimum_reveal_timeout}) for chain "
            f"{network.name} (chain-id: {network.value})"
        )

    if default_settle_timeout < default_reveal_timeout * 2:
        network = Networks(chain_id)
        raise ConfigurationError(
            f"Option `default-settle-timeout={default_settle_timeout}` should be higher than "
            f"two times the `default-reveal-timeout={default_reveal_timeout}`."
        )

    config = RaidenConfig(
        chain_id=chain_id,
        environment_type=environment_type,
        development_environment=development_environment,
        reveal_timeout=default_reveal_timeout,
        settle_timeout=default_settle_timeout,
        console=console,
        mediation_fees=fee_config,
        unrecoverable_error_should_crash=unrecoverable_error_should_crash,
        resolver_endpoint=resolver_endpoint,
        rest_api=rest_api_config,
        python_api=python_api_config,
        enable_tracing=enable_tracing,
    )
    config.blockchain.query_interval = blockchain_query_interval
    config.services.monitoring_enabled = enable_monitoring
    config.services.pathfinding_max_paths = pathfinding_max_paths
    config.transport.server = matrix_server
    return config


def run_raiden_service(
    config: RaidenConfig,
    eth_rpc_endpoint: str,
    address: Address,
    keystore_path: str,
    gas_price: Callable,
    user_deposit_contract_address: Optional[UserDepositAddress],
    sync_check: bool,
    password_file: TextIO,
    datadir: Optional[str],
    pathfinding_service_address: str,
    routing_mode: RoutingMode,
    **kwargs: Any,  # FIXME: not used here, but still receives stuff in smoketest
) -> RaidenService:
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    chain_id = config.chain_id
    token_network_registry_deployed_at: Optional[BlockNumber]
    smart_contracts_start_at: BlockNumber

    if datadir is None:
        datadir = os.path.join(os.path.expanduser("~"), ".raiden")

    account_manager = AccountManager(keystore_path)
    web3 = Web3(HTTPProvider(rpc_normalized_endpoint(eth_rpc_endpoint)))

    check_sql_version()
    check_ethereum_has_accounts(account_manager)
    check_ethereum_chain_id(chain_id, web3)

    address, privatekey = get_account_and_private_key(account_manager, address, password_file)

    contracts = load_deployed_contracts_data(config, chain_id, config.development_environment)

    rpc_client = JSONRPCClient(
        web3=web3,
        privkey=privatekey,
        gas_price_strategy=gas_price,
        block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    )

    token_network_registry_deployed_at = None
    if "TokenNetworkRegistry" in contracts:
        token_network_registry_deployed_at = BlockNumber(
            contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["block_number"]
        )

    if token_network_registry_deployed_at is None:
        smart_contracts_start_at = get_smart_contracts_start_at(chain_id)
    else:
        smart_contracts_start_at = token_network_registry_deployed_at

    proxy_manager = ProxyManager(
        rpc_client=rpc_client,
        contract_manager=ContractManager(config.contracts_path),
        metadata=ProxyManagerMetadata(
            token_network_registry_deployed_at=token_network_registry_deployed_at,
            filters_start_at=smart_contracts_start_at,
        ),
    )

    api_server: Optional[APIServer] = None
    if config.rest_api.rest_api_enabled:
        msg = "An eth_rpc_endpoint must be supplied for the Rest API when it is enabled"
        assert config.rest_api.eth_rpc_endpoint, msg
        api_server = start_api_server(
            rpc_client=rpc_client,
            config=config.rest_api,
            eth_rpc_endpoint=config.rest_api.eth_rpc_endpoint,
        )

    if sync_check:
        check_synced(rpc_client)

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
            raise RaidenError("The user deposit address is invalid")

        deployed_addresses = load_deployment_addresses_from_udc(
            proxy_manager=proxy_manager,
            user_deposit_address=user_deposit_contract_address,
            block_identifier=BLOCK_ID_LATEST,
        )
    else:
        deployed_addresses = load_deployment_addresses_from_contracts(contracts=contracts)

    # Load the available matrix servers when no matrix server is given
    # The list is used in a PFS check
    if config.transport.server == MATRIX_AUTO_SELECT_SERVER:
        fetch_available_matrix_servers(config.transport, config.environment_type)

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
        enable_monitoring=config.services.monitoring_enabled,
    )

    check_ethereum_confirmed_block_is_not_pruned(
        jsonrpc_client=rpc_client,
        secret_registry=raiden_bundle.secret_registry,
        confirmation_blocks=config.blockchain.confirmation_blocks,
    )

    database_path = Path(
        os.path.join(
            datadir,
            f"node_{pex(address)}",
            f"netid_{chain_id}",
            f"network_{pex(raiden_bundle.token_network_registry.address)}",
            f"v{RAIDEN_DB_VERSION}_log.db",
        )
    )
    config.database_path = database_path

    print(f"Raiden is running in {config.environment_type.value.lower()} mode")
    print(
        "\nYou are connected to the '{}' network and the DB path is: {}".format(
            ID_TO_CHAINNAME.get(chain_id, chain_id), database_path
        )
    )

    matrix_transport = MatrixTransport(
        config=config.transport,
        environment=config.environment_type,
        enable_tracing=config.enable_tracing,
    )

    event_handler: EventHandler = RaidenEventHandler()

    # User should be told how to set fees, if using default fee settings
    log.debug("Fee Settings", fee_settings=config.mediation_fees)
    has_default_fees = (
        len(config.mediation_fees.token_to_flat_fee) == 0
        and len(config.mediation_fees.token_to_proportional_fee) == 0
        and len(config.mediation_fees.token_to_proportional_imbalance_fee) == 0
    )
    if has_default_fees:
        click.secho(
            "Default fee settings are used. "
            "If you want use Raiden with mediation fees - flat, proportional and imbalance fees - "
            "see https://raiden-network.readthedocs.io/en/latest/overview_and_guide.html#run-it",  # noqa: E501
            fg="yellow",
        )

    # Only send feedback when PFS is used
    if routing_mode == RoutingMode.PFS:
        event_handler = PFSFeedbackEventHandler(event_handler)

    message_handler = MessageHandler()

    raiden_service = RaidenService(
        config=config,
        rpc_client=rpc_client,
        proxy_manager=proxy_manager,
        query_start_block=smart_contracts_start_at,
        raiden_bundle=raiden_bundle,
        services_bundle=services_bundle,
        transport=matrix_transport,
        raiden_event_handler=event_handler,
        message_handler=message_handler,
        routing_mode=routing_mode,
        api_server=api_server,
    )

    raiden_service.start()
    return raiden_service
