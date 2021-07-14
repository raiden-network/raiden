import os
import subprocess
from pathlib import Path

import gevent
import pytest
from gevent.event import AsyncResult

from raiden.constants import Environment, RoutingMode
from raiden.network.pathfinding import PFSInfo
from raiden.raiden_service import RaidenService
from raiden.settings import CapabilitiesConfig
from raiden.tests.utils import factories
from raiden.tests.utils.mocks import PFSMock
from raiden.tests.utils.network import (
    CHAIN,
    BlockchainServices,
    create_all_channels_for_network,
    create_apps,
    create_network_channels,
    create_sequential_channels,
    parallel_start_apps,
    wait_for_alarm_start,
    wait_for_channels,
    wait_for_token_networks,
)
from raiden.tests.utils.tests import shutdown_apps_and_cleanup_tasks
from raiden.tests.utils.transport import ParsedURL
from raiden.utils.formatting import to_canonical_address
from raiden.utils.typing import (
    BlockNumber,
    BlockTimeout,
    ChainID,
    Iterable,
    Iterator,
    List,
    MonitoringServiceAddress,
    OneToNAddress,
    Optional,
    Port,
    ServiceRegistryAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkRegistryAddress,
    UserDepositAddress,
)


def timeout(blockchain_type: str) -> float:
    """As parity nodes are slower, we need to set a longer timeout when
    waiting for onchain events to complete."""
    return 120 if blockchain_type == "parity" else 30


@pytest.fixture
def routing_mode():
    return RoutingMode.PFS


@pytest.fixture
def raiden_chain(
    token_addresses: List[TokenAddress],
    token_network_registry_address: TokenNetworkRegistryAddress,
    one_to_n_address: Optional[OneToNAddress],
    monitoring_service_address: MonitoringServiceAddress,
    channels_per_node: int,
    deposit: TokenAmount,
    settle_timeout: BlockTimeout,
    chain_id: ChainID,
    blockchain_services: BlockchainServices,
    reveal_timeout: BlockTimeout,
    retry_interval_initial: float,
    retry_interval_max: float,
    retries_before_backoff: int,
    environment_type: Environment,
    unrecoverable_error_should_crash: bool,
    local_matrix_servers: List[ParsedURL],
    blockchain_type: str,
    contracts_path: Path,
    user_deposit_address: UserDepositAddress,
    logs_storage: str,
    register_tokens: bool,
    start_raiden_apps: bool,
    routing_mode: RoutingMode,
    blockchain_query_interval: float,
    resolver_ports: List[Optional[int]],
    enable_rest_api: bool,
    port_generator: Iterator[Port],
    capabilities: CapabilitiesConfig,
) -> Iterable[List[RaidenService]]:

    if len(token_addresses) != 1:
        raise ValueError("raiden_chain only works with a single token")

    assert channels_per_node in (0, 1, 2, CHAIN), (
        "deployed_network uses create_sequential_network that can only work "
        "with 0, 1 or 2 channels"
    )

    base_datadir = os.path.join(logs_storage, "raiden_nodes")

    service_registry_address: Optional[ServiceRegistryAddress] = None
    if blockchain_services.service_registry:
        service_registry_address = blockchain_services.service_registry.address
    raiden_apps = create_apps(
        chain_id=chain_id,
        blockchain_services=blockchain_services.blockchain_services,
        token_network_registry_address=token_network_registry_address,
        one_to_n_address=one_to_n_address,
        secret_registry_address=blockchain_services.secret_registry.address,
        service_registry_address=service_registry_address,
        user_deposit_address=user_deposit_address,
        monitoring_service_contract_address=monitoring_service_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        database_basedir=base_datadir,
        retry_interval_initial=retry_interval_initial,
        retry_interval_max=retry_interval_max,
        retries_before_backoff=retries_before_backoff,
        environment_type=environment_type,
        unrecoverable_error_should_crash=unrecoverable_error_should_crash,
        local_matrix_url=local_matrix_servers[0],
        contracts_path=contracts_path,
        routing_mode=routing_mode,
        blockchain_query_interval=blockchain_query_interval,
        resolver_ports=resolver_ports,
        enable_rest_api=enable_rest_api,
        port_generator=port_generator,
        capabilities_config=capabilities,
    )

    confirmed_block = BlockNumber(raiden_apps[0].confirmation_blocks + 1)
    blockchain_services.proxy_manager.client.wait_until_block(target_block_number=confirmed_block)

    if start_raiden_apps:
        parallel_start_apps(raiden_apps)

        if register_tokens:
            exception = RuntimeError(
                "`raiden_chain` fixture setup failed, token networks unavailable"
            )
            with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
                wait_for_token_networks(
                    raiden_apps=raiden_apps,
                    token_network_registry_address=token_network_registry_address,
                    token_addresses=token_addresses,
                )

    app_channels = create_sequential_channels(raiden_apps, channels_per_node)

    create_all_channels_for_network(
        app_channels=app_channels,
        token_addresses=token_addresses,
        channel_individual_deposit=deposit,
        channel_settle_timeout=settle_timeout,
    )

    if start_raiden_apps:
        exception = RuntimeError("`raiden_chain` fixture setup failed, nodes are unreachable")
        with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
            wait_for_channels(
                app_channels=app_channels,
                token_network_registry_address=blockchain_services.deploy_registry.address,
                token_addresses=token_addresses,
                deposit=deposit,
            )

    yield raiden_apps

    shutdown_apps_and_cleanup_tasks(raiden_apps)


@pytest.fixture
def resolvers(resolver_ports):
    """Invoke resolver process for each node having a resolver port

    By default, Raiden nodes start without hash resolvers (all ports are None)
    """
    resolvers = []
    for port in resolver_ports:
        resolver = None
        if port is not None:
            args = ["python", "tools/dummy_resolver_server.py", str(port)]
            resolver = subprocess.Popen(args, stdout=subprocess.PIPE)
            assert resolver.poll() is None
        resolvers.append(resolver)

    yield resolvers

    for resolver in resolvers:
        if resolver is not None:
            resolver.terminate()


@pytest.fixture
def adhoc_capability():
    return False


@pytest.fixture
def capabilities(adhoc_capability) -> CapabilitiesConfig:
    config = CapabilitiesConfig()
    if adhoc_capability:
        config.adhoc_capability = adhoc_capability  # type: ignore
    return config


@pytest.fixture
def pfs_mock(
    monkeypatch,
    local_matrix_servers,
    chain_id,
    token_network_registry_address,
    user_deposit_address,
):

    pfs_info = PFSInfo(
        url="http://mock_pfs",
        chain_id=chain_id,
        token_network_registry_address=TokenNetworkRegistryAddress(
            to_canonical_address(token_network_registry_address or factories.make_address())
        ),
        user_deposit_address=to_canonical_address(
            user_deposit_address or factories.make_address()
        ),
        payment_address=to_canonical_address(factories.make_address()),
        confirmed_block_number=BlockNumber(0),
        message="",
        operator="",
        version="",
        price=TokenAmount(0),
        matrix_server=local_matrix_servers[0],
    )

    pfs_mock = PFSMock(pfs_info)

    # NOTE: pfs_mock.add_apps() has to be called in the test in order to make the monkeypatched
    # methods useful

    # Patch the relevant functions in Raiden with the ones of the Mock:
    # Methods used by initiator
    monkeypatch.setattr(
        "raiden.network.pathfinding._query_address_metadata", pfs_mock.query_address_metadata
    )
    monkeypatch.setattr("raiden.routing.get_best_routes_pfs", pfs_mock.get_best_routes_pfs)
    # PFS info endpoint
    monkeypatch.setattr("raiden.network.pathfinding.get_pfs_info", pfs_mock.get_pfs_info)

    return pfs_mock


@pytest.fixture
def raiden_network(
    token_addresses: List[TokenAddress],
    token_network_registry_address: TokenNetworkRegistryAddress,
    one_to_n_address: Optional[OneToNAddress],
    monitoring_service_address: MonitoringServiceAddress,
    channels_per_node: int,
    deposit: TokenAmount,
    settle_timeout: BlockTimeout,
    chain_id: ChainID,
    blockchain_services: BlockchainServices,
    reveal_timeout: BlockTimeout,
    retry_interval_initial: float,
    retry_interval_max: float,
    retries_before_backoff: int,
    environment_type: Environment,
    unrecoverable_error_should_crash: bool,
    local_matrix_servers: List[ParsedURL],
    blockchain_type: str,
    contracts_path: Path,
    user_deposit_address: Optional[UserDepositAddress],
    logs_storage: str,
    register_tokens: bool,
    start_raiden_apps: bool,
    routing_mode: RoutingMode,
    blockchain_query_interval: float,
    resolver_ports: List[Optional[int]],
    enable_rest_api: bool,
    port_generator: Iterator[Port],
    capabilities: CapabilitiesConfig,
) -> Iterable[List[RaidenService]]:
    service_registry_address = None
    if blockchain_services.service_registry:
        service_registry_address = blockchain_services.service_registry.address

    base_datadir = os.path.join(logs_storage, "raiden_nodes")

    raiden_apps = create_apps(
        chain_id=chain_id,
        contracts_path=contracts_path,
        blockchain_services=blockchain_services.blockchain_services,
        token_network_registry_address=token_network_registry_address,
        secret_registry_address=blockchain_services.secret_registry.address,
        service_registry_address=service_registry_address,
        one_to_n_address=one_to_n_address,
        user_deposit_address=user_deposit_address,
        monitoring_service_contract_address=monitoring_service_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        database_basedir=base_datadir,
        retry_interval_initial=retry_interval_initial,
        retry_interval_max=retry_interval_max,
        retries_before_backoff=retries_before_backoff,
        environment_type=environment_type,
        unrecoverable_error_should_crash=unrecoverable_error_should_crash,
        local_matrix_url=local_matrix_servers[0],
        routing_mode=routing_mode,
        blockchain_query_interval=blockchain_query_interval,
        resolver_ports=resolver_ports,
        enable_rest_api=enable_rest_api,
        port_generator=port_generator,
        capabilities_config=capabilities,
    )

    confirmed_block = BlockNumber(raiden_apps[0].confirmation_blocks + 1)
    blockchain_services.proxy_manager.client.wait_until_block(target_block_number=confirmed_block)

    if start_raiden_apps:
        parallel_start_apps(raiden_apps)

        if register_tokens:
            exception = RuntimeError(
                "`raiden_chain` fixture setup failed, token networks unavailable"
            )
            with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
                wait_for_token_networks(
                    raiden_apps=raiden_apps,
                    token_network_registry_address=token_network_registry_address,
                    token_addresses=token_addresses,
                )

    app_channels = create_network_channels(raiden_apps, channels_per_node)

    create_all_channels_for_network(
        app_channels=app_channels,
        token_addresses=token_addresses,
        channel_individual_deposit=deposit,
        channel_settle_timeout=settle_timeout,
    )

    if start_raiden_apps:
        exception = RuntimeError("`raiden_network` fixture setup failed, nodes are unreachable")
        with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
            wait_for_channels(
                app_channels=app_channels,
                token_network_registry_address=blockchain_services.deploy_registry.address,
                token_addresses=token_addresses,
                deposit=deposit,
            )

        # Force blocknumber update
        exception = RuntimeError("Alarm failed to start and set up start_block correctly")

        with gevent.Timeout(seconds=5, exception=exception):
            wait_for_alarm_start(raiden_apps)

    yield raiden_apps

    shutdown_apps_and_cleanup_tasks(raiden_apps)


class RestartNode:
    def __init__(self):
        self.async_result: Optional[AsyncResult] = None

    def link_exception_to(self, result: AsyncResult) -> None:
        self.async_result = result

    def __call__(self, service: RaidenService) -> None:
        if self.async_result is not None:
            service.greenlet.link_exception(self.async_result)
        service.start()


@pytest.fixture
def restart_node() -> RestartNode:
    return RestartNode()
