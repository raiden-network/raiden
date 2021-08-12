""" Utilities to set-up a Raiden network. """
from dataclasses import dataclass
from itertools import product
from pathlib import Path

import gevent
import structlog
from web3 import Web3

from raiden import waiting
from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER, Environment, RoutingMode
from raiden.exceptions import PFSReturnedError
from raiden.network.pathfinding import PFSProxy
from raiden.network.proxies.proxy_manager import ProxyManager, ProxyManagerMetadata
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    DEFAULT_RETRY_TIMEOUT,
    BlockchainConfig,
    CapabilitiesConfig,
    MatrixTransportConfig,
    MediationFeeConfig,
    RaidenConfig,
    RestApiConfig,
    ServiceConfig,
)
from raiden.tests.utils.app import database_from_privatekey
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.tests.utils.protocol import HoldRaidenEventHandler, WaitForMessage
from raiden.tests.utils.transport import ParsedURL, TestMatrixTransport
from raiden.transfer import views
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.views import (
    get_channelstate_by_canonical_identifier,
    get_channelstate_by_token_network_and_partner,
    state_from_raiden,
)
from raiden.ui.app import start_api_server
from raiden.ui.startup import RaidenBundle, ServicesBundle
from raiden.utils.formatting import to_checksum_address, to_hex_address
from raiden.utils.typing import (
    Address,
    BlockIdentifier,
    BlockNumber,
    BlockTimeout,
    ChainID,
    Host,
    Iterable,
    Iterator,
    List,
    MonitoringServiceAddress,
    OneToNAddress,
    Optional,
    Port,
    PrivateKey,
    SecretRegistryAddress,
    ServiceRegistryAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    Tuple,
    UserDepositAddress,
)
from raiden.waiting import wait_for_token_network
from raiden_contracts.contract_manager import ContractManager

AppChannels = Iterable[Tuple[RaidenService, RaidenService]]

log = structlog.get_logger(__name__)

CHAIN = object()  # Flag used by create a network does make a loop with the channels


@dataclass
class BlockchainServices:
    deploy_registry: TokenNetworkRegistry
    secret_registry: SecretRegistry
    service_registry: Optional[ServiceRegistry]
    proxy_manager: ProxyManager
    blockchain_services: List[ProxyManager]


def check_channel(
    app1: RaidenService,
    app2: RaidenService,
    token_network_address: TokenNetworkAddress,
    settle_timeout: BlockTimeout,
    deposit_amount: TokenAmount,
) -> None:
    channel_state1 = get_channelstate_by_token_network_and_partner(
        chain_state=state_from_raiden(app1),
        token_network_address=token_network_address,
        partner_address=app2.address,
    )
    assert channel_state1, "app1 does not have a channel with app2."
    netcontract1 = app1.proxy_manager.payment_channel(
        channel_state=channel_state1, block_identifier=BLOCK_ID_LATEST
    )

    channel_state2 = get_channelstate_by_token_network_and_partner(
        chain_state=state_from_raiden(app2),
        token_network_address=token_network_address,
        partner_address=app1.address,
    )
    assert channel_state2, "app2 does not have a channel with app1."
    netcontract2 = app2.proxy_manager.payment_channel(
        channel_state=channel_state2, block_identifier=BLOCK_ID_LATEST
    )

    # Check a valid settle timeout was used, the netting contract has an
    # enforced minimum and maximum
    assert settle_timeout == netcontract1.settle_timeout()
    assert settle_timeout == netcontract2.settle_timeout()

    if deposit_amount > 0:
        assert netcontract1.can_transfer(BLOCK_ID_LATEST)
        assert netcontract2.can_transfer(BLOCK_ID_LATEST)

    app1_details = netcontract1.detail(BLOCK_ID_LATEST)
    app2_details = netcontract2.detail(BLOCK_ID_LATEST)

    assert (
        app1_details.participants_data.our_details.address
        == app2_details.participants_data.partner_details.address
    )
    assert (
        app1_details.participants_data.partner_details.address
        == app2_details.participants_data.our_details.address
    )

    assert (
        app1_details.participants_data.our_details.deposit
        == app2_details.participants_data.partner_details.deposit
    )
    assert (
        app1_details.participants_data.partner_details.deposit
        == app2_details.participants_data.our_details.deposit
    )
    assert app1_details.chain_id == app2_details.chain_id

    assert app1_details.participants_data.our_details.deposit == deposit_amount
    assert app1_details.participants_data.partner_details.deposit == deposit_amount
    assert app2_details.participants_data.our_details.deposit == deposit_amount
    assert app2_details.participants_data.partner_details.deposit == deposit_amount
    assert app2_details.chain_id == UNIT_CHAIN_ID


def payment_channel_open_and_deposit(
    app0: RaidenService,
    app1: RaidenService,
    token_address: TokenAddress,
    deposit: TokenAmount,
    settle_timeout: BlockTimeout,
) -> None:
    """Open a new channel with app0 and app1 as participants"""
    assert token_address

    block_identifier: BlockIdentifier
    if app0.wal:
        block_identifier = views.get_confirmed_blockhash(app0)
    else:
        block_identifier = BLOCK_ID_LATEST
    token_network_address = app0.default_registry.get_token_network(
        token_address=token_address, block_identifier=block_identifier
    )
    assert token_network_address, "request a channel for an unregistered token"
    token_network_proxy = app0.proxy_manager.token_network(
        token_network_address, block_identifier=BLOCK_ID_LATEST
    )

    channel_details = token_network_proxy.new_netting_channel(
        partner=app1.address,
        settle_timeout=settle_timeout,
        given_block_identifier=block_identifier,
    )
    channel_identifier = channel_details.channel_identifier
    assert channel_identifier

    if deposit != 0:
        for app, partner in [(app0, app1), (app1, app0)]:
            waiting.wait_for_newchannel(
                raiden=app,
                token_network_registry_address=app.default_registry.address,
                token_address=token_address,
                partner_address=partner.address,
                retry_timeout=0.5,
            )

            chain_state = state_from_raiden(app)
            canonical_identifier = CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=token_network_proxy.address,
                channel_identifier=channel_identifier,
            )
            channel_state = get_channelstate_by_canonical_identifier(
                chain_state=chain_state, canonical_identifier=canonical_identifier
            )
            assert channel_state, "nodes dont share a channel"

            # Use each app's own chain because of the private key / local signing
            token = app.proxy_manager.token(token_address, BLOCK_ID_LATEST)
            payment_channel_proxy = app.proxy_manager.payment_channel(
                channel_state=channel_state, block_identifier=BLOCK_ID_LATEST
            )

            # This check can succeed and the deposit still fail, if channels are
            # openned in parallel
            previous_balance = token.balance_of(app.address)
            assert previous_balance >= deposit

            # the payment channel proxy will call approve
            # token.approve(token_network_proxy.address, deposit)
            payment_channel_proxy.approve_and_set_total_deposit(
                total_deposit=deposit, block_identifier=BLOCK_ID_LATEST
            )

            # Balance must decrease by at least but not exactly `deposit` amount,
            # because channels can be openned in parallel
            new_balance = token.balance_of(app.address)
            assert new_balance <= previous_balance - deposit

        check_channel(app0, app1, token_network_proxy.address, settle_timeout, deposit)


def create_all_channels_for_network(
    app_channels: AppChannels,
    token_addresses: List[TokenAddress],
    channel_individual_deposit: TokenAmount,
    channel_settle_timeout: BlockTimeout,
) -> None:
    greenlets = set()
    for token_address in token_addresses:
        for app_pair in app_channels:
            greenlets.add(
                gevent.spawn(
                    payment_channel_open_and_deposit,
                    app_pair[0],
                    app_pair[1],
                    token_address,
                    channel_individual_deposit,
                    channel_settle_timeout,
                )
            )
    gevent.joinall(greenlets, raise_error=True)

    channels = [
        {
            "app0": to_hex_address(app0.address),
            "app1": to_hex_address(app1.address),
            "deposit": channel_individual_deposit,
            "token_address": to_hex_address(token_address),
        }
        for (app0, app1), token_address in product(app_channels, token_addresses)
    ]
    log.info("Test channels", channels=channels)


def network_with_minimum_channels(
    apps: List[RaidenService], channels_per_node: int
) -> AppChannels:
    """Return the channels that should be created so that each app has at
    least `channels_per_node` with the other apps.

    Yields a two-tuple (app1, app2) that must be connected to respect
    `channels_per_node`. Any preexisting channels will be ignored, so the nodes
    might end up with more channels open than `channels_per_node`.
    """
    # pylint: disable=too-many-locals
    if channels_per_node > len(apps):
        raise ValueError("Can't create more channels than nodes")

    if len(apps) == 1:
        raise ValueError("Can't create channels with only one node")

    # If we use random nodes we can hit some edge cases, like the
    # following:
    #
    #  node | #channels
    #   A   |    0
    #   B   |    1  D-B
    #   C   |    1  D-C
    #   D   |    2  D-C D-B
    #
    # B and C have one channel each, and they do not a channel
    # between them, if in this iteration either app is the current
    # one and random choose the other to connect, A will be left
    # with no channels. In this scenario we need to force the use
    # of the node with the least number of channels.

    unconnected_apps = {}
    channel_count = {}

    # assume that the apps don't have any connection among them
    for curr_app in apps:
        all_apps = list(apps)
        all_apps.remove(curr_app)
        unconnected_apps[curr_app.address] = all_apps
        channel_count[curr_app.address] = 0

    # Create `channels_per_node` channels for each token in each app
    # for token_address, curr_app in product(tokens_list, sorted(apps, key=sort_by_address)):

    # sorting the apps and use the next n apps to make a channel to avoid edge
    # cases
    for curr_app in sorted(apps, key=lambda app: app.address):
        available_apps = unconnected_apps[curr_app.address]

        while channel_count[curr_app.address] < channels_per_node:
            least_connect = sorted(available_apps, key=lambda app: channel_count[app.address])[0]

            channel_count[curr_app.address] += 1
            available_apps.remove(least_connect)

            channel_count[least_connect.address] += 1
            unconnected_apps[least_connect.address].remove(curr_app)

            yield curr_app, least_connect


def create_network_channels(
    raiden_apps: List[RaidenService], channels_per_node: int
) -> AppChannels:
    app_channels: AppChannels

    num_nodes = len(raiden_apps)

    if channels_per_node is not CHAIN and channels_per_node > num_nodes:
        raise ValueError("Can't create more channels than nodes")

    if channels_per_node == 0:
        app_channels = []
    elif channels_per_node == CHAIN:
        app_channels = list(zip(raiden_apps[:-1], raiden_apps[1:]))
    else:
        app_channels = list(network_with_minimum_channels(raiden_apps, channels_per_node))

    return app_channels


def create_sequential_channels(
    raiden_apps: List[RaidenService], channels_per_node: int
) -> AppChannels:
    """Create a fully connected network with `num_nodes`, the nodes are
    connect sequentially.

    Returns:
        A list of apps of size `num_nodes`, with the property that every
        sequential pair in the list has an open channel with `deposit` for each
        participant.
    """
    app_channels: AppChannels

    num_nodes = len(raiden_apps)

    if num_nodes < 2:
        raise ValueError("cannot create a network with less than two nodes")

    if channels_per_node not in (0, 1, 2, CHAIN):
        raise ValueError("can only create networks with 0, 1, 2 or CHAIN channels")

    if channels_per_node == 0:
        app_channels = []

    if channels_per_node == 1:
        assert len(raiden_apps) % 2 == 0, "needs an even number of nodes"
        every_two = iter(raiden_apps)
        app_channels = list(zip(every_two, every_two))

    if channels_per_node == 2:
        app_channels = list(zip(raiden_apps, raiden_apps[1:] + [raiden_apps[0]]))

    if channels_per_node == CHAIN:
        app_channels = list(zip(raiden_apps[:-1], raiden_apps[1:]))

    return app_channels


def create_apps(
    chain_id: ChainID,
    contracts_path: Path,
    blockchain_services: List[ProxyManager],
    token_network_registry_address: TokenNetworkRegistryAddress,
    one_to_n_address: Optional[OneToNAddress],
    secret_registry_address: SecretRegistryAddress,
    service_registry_address: Optional[ServiceRegistryAddress],
    user_deposit_address: Optional[UserDepositAddress],
    monitoring_service_contract_address: MonitoringServiceAddress,
    reveal_timeout: BlockTimeout,
    settle_timeout: BlockTimeout,
    database_basedir: str,
    retry_interval_initial: float,
    retry_interval_max: float,
    retries_before_backoff: int,
    environment_type: Environment,
    unrecoverable_error_should_crash: bool,
    local_matrix_url: Optional[ParsedURL],
    routing_mode: RoutingMode,
    blockchain_query_interval: float,
    resolver_ports: List[Optional[int]],
    enable_rest_api: bool,
    port_generator: Iterator[Port],
    capabilities_config: CapabilitiesConfig,
) -> List[RaidenService]:
    """Create the apps."""
    # pylint: disable=too-many-locals
    apps: List[RaidenService] = []
    for idx, proxy_manager in enumerate(blockchain_services):
        database_path = database_from_privatekey(base_dir=database_basedir, app_number=idx)
        assert len(resolver_ports) > idx
        resolver_port = resolver_ports[idx]

        config = RaidenConfig(
            chain_id=chain_id,
            environment_type=environment_type,
            unrecoverable_error_should_crash=unrecoverable_error_should_crash,
            reveal_timeout=reveal_timeout,
            settle_timeout=settle_timeout,
            contracts_path=contracts_path,
            database_path=database_path,
            blockchain=BlockchainConfig(
                confirmation_blocks=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
                query_interval=blockchain_query_interval,
            ),
            mediation_fees=MediationFeeConfig(),
            services=ServiceConfig(monitoring_enabled=False),
            rest_api=RestApiConfig(
                rest_api_enabled=enable_rest_api, host=Host("localhost"), port=next(port_generator)
            ),
            console=False,
            transport_type="matrix",
        )
        config.transport.capabilities_config = capabilities_config

        if local_matrix_url is not None:
            config.transport = MatrixTransportConfig(
                retries_before_backoff=retries_before_backoff,
                retry_interval_initial=retry_interval_initial,
                retry_interval_max=retry_interval_max,
                server=local_matrix_url,
                available_servers=[],
                capabilities_config=capabilities_config,
            )

        assert config.transport.capabilities_config is not None
        if resolver_port is not None:
            config.resolver_endpoint = f"http://localhost:{resolver_port}"

        registry = proxy_manager.token_network_registry(
            token_network_registry_address, block_identifier=BLOCK_ID_LATEST
        )
        secret_registry = proxy_manager.secret_registry(
            secret_registry_address, block_identifier=BLOCK_ID_LATEST
        )

        services_bundle = None
        if user_deposit_address:
            user_deposit = proxy_manager.user_deposit(
                user_deposit_address, block_identifier=BLOCK_ID_LATEST
            )

            service_registry: Optional[ServiceRegistry] = None
            if service_registry_address:
                service_registry = proxy_manager.service_registry(
                    service_registry_address, block_identifier=BLOCK_ID_LATEST
                )

            monitoring_service = None
            if monitoring_service_contract_address:
                monitoring_service = proxy_manager.monitoring_service(
                    monitoring_service_contract_address, block_identifier=BLOCK_ID_LATEST
                )

            one_to_n = None
            if one_to_n_address:
                one_to_n = proxy_manager.one_to_n(
                    one_to_n_address, block_identifier=BLOCK_ID_LATEST
                )

            services_bundle = ServicesBundle(
                user_deposit, service_registry, monitoring_service, one_to_n
            )

        # Use `TestMatrixTransport` that saves sent messages for assertions in tests
        assert config.transport.capabilities_config is not None
        transport = TestMatrixTransport(config=config.transport, environment=environment_type)

        raiden_event_handler = RaidenEventHandler()
        hold_handler = HoldRaidenEventHandler(raiden_event_handler)
        message_handler = WaitForMessage()

        api_server = None
        if enable_rest_api:
            api_server = start_api_server(
                rpc_client=proxy_manager.client, config=config.rest_api, eth_rpc_endpoint="bla"
            )

        app = RaidenService(
            config=config,
            rpc_client=proxy_manager.client,
            proxy_manager=proxy_manager,
            query_start_block=BlockNumber(0),
            raiden_bundle=RaidenBundle(registry, secret_registry),
            services_bundle=services_bundle,
            transport=transport,
            raiden_event_handler=hold_handler,
            message_handler=message_handler,
            routing_mode=routing_mode,
            api_server=api_server,
            pfs_proxy=SimplePFSProxy(apps),
        )
        apps.append(app)

    return apps


class SimplePFSProxy(PFSProxy):
    def __init__(self, services):
        self._services = services

    def query_address_metadata(self, address):
        for service in self._services:
            if service.address == address:
                return service.transport.address_metadata
        raise PFSReturnedError(message="Address not found", error_code=404, error_details={})

    def set_services(self, services):
        self._services = services


def parallel_start_apps(raiden_apps: List[RaidenService]) -> None:
    """Start all the raiden apps in parallel."""
    start_tasks = set()

    for app in raiden_apps:
        greenlet = gevent.spawn(app.start)
        greenlet.name = f"Fixture:raiden_network node:{to_checksum_address(app.address)}"
        start_tasks.add(greenlet)

    gevent.joinall(start_tasks, raise_error=True)

    addresses_in_order = {pos: to_hex_address(app.address) for pos, app in enumerate(raiden_apps)}
    log.info("Raiden Apps started", addresses_in_order=addresses_in_order)


def jsonrpc_services(
    proxy_manager: ProxyManager,
    private_keys: List[PrivateKey],
    secret_registry_address: SecretRegistryAddress,
    service_registry_address: Optional[ServiceRegistryAddress],
    token_network_registry_address: TokenNetworkRegistryAddress,
    web3: Web3,
    contract_manager: ContractManager,
) -> BlockchainServices:
    block_identifier = BLOCK_ID_LATEST
    secret_registry = proxy_manager.secret_registry(
        secret_registry_address, block_identifier=block_identifier
    )
    service_registry = None
    if service_registry_address:
        service_registry = proxy_manager.service_registry(
            service_registry_address, block_identifier=block_identifier
        )
    deploy_registry = proxy_manager.token_network_registry(
        token_network_registry_address, block_identifier=block_identifier
    )

    blockchain_services = []
    for privkey in private_keys:
        rpc_client = JSONRPCClient(web3, privkey)
        proxy_manager = ProxyManager(
            rpc_client=rpc_client,
            contract_manager=contract_manager,
            metadata=ProxyManagerMetadata(
                token_network_registry_deployed_at=GENESIS_BLOCK_NUMBER,
                filters_start_at=GENESIS_BLOCK_NUMBER,
            ),
        )
        blockchain_services.append(proxy_manager)

    return BlockchainServices(
        deploy_registry=deploy_registry,
        secret_registry=secret_registry,
        service_registry=service_registry,
        proxy_manager=proxy_manager,
        blockchain_services=blockchain_services,
    )


def wait_for_alarm_start(
    raiden_apps: List[RaidenService], retry_timeout: float = DEFAULT_RETRY_TIMEOUT
) -> None:
    """Wait until all Alarm tasks start & set up the last_block"""
    apps = list(raiden_apps)

    while apps:
        app = apps[-1]

        if app.alarm.known_block_number is None:
            gevent.sleep(retry_timeout)
        else:
            apps.pop()


def wait_for_usable_channel(
    raiden: RaidenService,
    partner_address: Address,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    our_deposit: TokenAmount,
    partner_deposit: TokenAmount,
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    """Wait until the channel from app0 to app1 is usable.

    The channel and the deposits are registered, and the partner network state
    is reachable.
    """
    waiting.wait_for_newchannel(
        raiden=raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        partner_address=partner_address,
        retry_timeout=retry_timeout,
    )

    # wait for our deposit
    waiting.wait_for_participant_deposit(
        raiden=raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        partner_address=partner_address,
        target_address=raiden.address,
        target_balance=our_deposit,
        retry_timeout=retry_timeout,
    )

    # wait for the partner deposit
    waiting.wait_for_participant_deposit(
        raiden=raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        partner_address=partner_address,
        target_address=partner_address,
        target_balance=partner_deposit,
        retry_timeout=retry_timeout,
    )


def wait_for_token_networks(
    raiden_apps: List[RaidenService],
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_addresses: List[TokenAddress],
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    for token_address in token_addresses:
        for app in raiden_apps:
            wait_for_token_network(
                app, token_network_registry_address, token_address, retry_timeout
            )


def wait_for_channels(
    app_channels: AppChannels,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_addresses: List[TokenAddress],
    deposit: TokenAmount,
    retry_timeout: float = DEFAULT_RETRY_TIMEOUT,
) -> None:
    """Wait until all channels are usable from both directions."""

    for app0, app1 in app_channels:
        for token_address in token_addresses:
            # app0 waits for the channel to be usable
            wait_for_usable_channel(
                raiden=app0,
                partner_address=app1.address,
                token_network_registry_address=token_network_registry_address,
                token_address=token_address,
                our_deposit=deposit,
                partner_deposit=deposit,
                retry_timeout=retry_timeout,
            )
            # app1 waits for the channel to be usable
            wait_for_usable_channel(
                raiden=app1,
                partner_address=app0.address,
                token_network_registry_address=token_network_registry_address,
                token_address=token_address,
                our_deposit=deposit,
                partner_deposit=deposit,
                retry_timeout=retry_timeout,
            )
