from dataclasses import dataclass
from typing import Any, Dict, Optional

import click
from eth_utils import to_canonical_address

from raiden.constants import BLOCK_ID_LATEST, Environment, RoutingMode
from raiden.exceptions import RaidenError
from raiden.network.pathfinding import PFSConfig, check_pfs_for_production, configure_pfs_or_exit
from raiden.network.proxies.monitoring_service import MonitoringService
from raiden.network.proxies.one_to_n import OneToN
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.settings import RAIDEN_CONTRACT_VERSION, RaidenConfig
from raiden.ui.checks import DeploymentAddresses, check_pfs_configuration, check_raiden_environment
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    BlockIdentifier,
    Callable,
    ChainID,
    List,
    MonitoringServiceAddress,
    OneToNAddress,
    SecretRegistryAddress,
    ServiceRegistryAddress,
    TokenNetworkRegistryAddress,
    Tuple,
    UserDepositAddress,
    cast,
)
from raiden_contracts.constants import (
    CONTRACT_MONITORING_SERVICE,
    CONTRACT_ONE_TO_N,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    CONTRACT_USER_DEPOSIT,
    ID_TO_CHAINNAME,
)
from raiden_contracts.contract_manager import (
    ContractDevEnvironment,
    contracts_precompiled_path,
    get_contracts_deployment_info,
)


@dataclass(frozen=True)
class RaidenBundle:
    token_network_registry: TokenNetworkRegistry
    secret_registry: SecretRegistry

    def __post_init__(self) -> None:
        secret_registry_address = self.token_network_registry.get_secret_registry_address(
            BLOCK_ID_LATEST
        )
        if secret_registry_address != self.secret_registry.address:
            click.secho(
                f"Secret registry address linked with the token network registry "
                f"{to_checksum_address(secret_registry_address)} does not match "
                f"the address provided by the secret registry proxy "
                f"{to_checksum_address(self.secret_registry.address)}"
            )


@dataclass(frozen=True)
class ServicesBundle:
    user_deposit: UserDeposit
    service_registry: Optional[ServiceRegistry]
    monitoring_service: Optional[MonitoringService]
    one_to_n: Optional[OneToN]

    def __post_init__(self) -> None:
        block_identifier = BLOCK_ID_LATEST
        user_deposit_address = self.user_deposit.address
        token_address = self.user_deposit.token_address(block_identifier)

        monitoring_service_address = self.user_deposit.monitoring_service_address(block_identifier)

        # Validation should only be done if monitoring is enabled or PFS is used
        if (
            self.monitoring_service is None
            or self.service_registry is None
            or self.one_to_n is None
        ):
            return

        if monitoring_service_address != self.monitoring_service.address:
            click.secho(
                f"Monitoring service address linked with the user deposit contract "
                f"{to_checksum_address(monitoring_service_address)} does not match "
                f"the address provided by the monitoring service proxy "
                f"{to_checksum_address(self.monitoring_service.address)}"
            )
        one_to_n_address = self.user_deposit.one_to_n_address(block_identifier)
        if one_to_n_address != self.one_to_n.address:
            click.secho(
                f"OneToN address linked with the user deposit contract "
                f"{to_checksum_address(one_to_n_address)} does not match "
                f"the address provided by the OneToN proxy "
                f"{to_checksum_address(self.one_to_n.address)}"
            )
        service_registry_address = self.monitoring_service.service_registry_address(
            block_identifier
        )
        if service_registry_address != self.service_registry.address:
            click.secho(
                f"The service registry address linked with the monitoring service contract "
                f"{to_checksum_address(service_registry_address)} does not match "
                f"the address provided by the service registry proxy "
                f"{to_checksum_address(self.service_registry.address)}"
            )

        token_address_matches_monitoring_service = (
            token_address == self.monitoring_service.token_address(block_identifier)
        )
        if not token_address_matches_monitoring_service:
            raise RaidenError(
                f"The token used in the provided user deposit contract "
                f"{to_checksum_address(user_deposit_address)} does not match the one in the "
                f"MonitoringService contract {to_checksum_address(monitoring_service_address)}."
            )

        token_address_matches_service_registry = (
            token_address == self.service_registry.token_address(block_identifier)
        )
        if not token_address_matches_service_registry:
            raise RaidenError(
                f"The token used in the provided user deposit contract "
                f"{to_checksum_address(user_deposit_address)} does not match the one in the "
                f"ServiceRegistry contract {to_checksum_address(monitoring_service_address)}."
            )


def load_deployed_contracts_data(
    config: RaidenConfig,
    chain_id: ChainID,
    development_environment: ContractDevEnvironment = ContractDevEnvironment.DEMO,
) -> Dict[str, Any]:
    """Sets the contract deployment data depending on the network id and environment type

    If an invalid combination of network id and environment type is provided, exits
    the program with an error
    """
    check_raiden_environment(chain_id, config.environment_type)

    deployed_contracts_data: Dict[str, Any] = {}
    contracts_version = RAIDEN_CONTRACT_VERSION

    config.contracts_path = contracts_precompiled_path(contracts_version)

    if chain_id in ID_TO_CHAINNAME and ID_TO_CHAINNAME[chain_id] != "smoketest":
        deployment_data = get_contracts_deployment_info(
            chain_id=chain_id,
            version=contracts_version,
            development_environment=development_environment,
        )
        if not deployment_data:
            return deployed_contracts_data

        deployed_contracts_data = deployment_data["contracts"]

    return deployed_contracts_data


def load_deployment_addresses_from_contracts(contracts: Dict[str, Any]) -> DeploymentAddresses:
    return DeploymentAddresses(
        token_network_registry_address=TokenNetworkRegistryAddress(
            to_canonical_address(contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["address"])
        ),
        secret_registry_address=SecretRegistryAddress(
            to_canonical_address(contracts[CONTRACT_SECRET_REGISTRY]["address"])
        ),
        user_deposit_address=UserDepositAddress(
            to_canonical_address(contracts[CONTRACT_USER_DEPOSIT]["address"])
        ),
        service_registry_address=ServiceRegistryAddress(
            to_canonical_address(contracts[CONTRACT_SERVICE_REGISTRY]["address"])
        ),
        monitoring_service_address=MonitoringServiceAddress(
            to_canonical_address(contracts[CONTRACT_MONITORING_SERVICE]["address"])
        ),
        one_to_n_address=OneToNAddress(
            to_canonical_address(contracts[CONTRACT_ONE_TO_N]["address"])
        ),
    )


def load_deployment_addresses_from_udc(
    proxy_manager: ProxyManager,
    user_deposit_address: UserDepositAddress,
    block_identifier: BlockIdentifier,
) -> DeploymentAddresses:
    """Given a user deposit address, this function returns the list of contract addresses
    which are used as services which are bound to the user deposit contract deployed.
    """
    block_identifier = BLOCK_ID_LATEST
    user_deposit = proxy_manager.user_deposit(
        UserDepositAddress(to_canonical_address(user_deposit_address)),
        block_identifier=block_identifier,
    )
    monitoring_service_address = user_deposit.monitoring_service_address(block_identifier)
    one_to_n_address = user_deposit.one_to_n_address(block_identifier=block_identifier)

    monitoring_service_proxy = proxy_manager.monitoring_service(
        address=monitoring_service_address, block_identifier=block_identifier
    )

    token_network_registry_address = monitoring_service_proxy.token_network_registry_address(
        block_identifier=block_identifier
    )

    token_network_registry_proxy = proxy_manager.token_network_registry(
        token_network_registry_address, block_identifier=block_identifier
    )
    secret_registry_address = token_network_registry_proxy.get_secret_registry_address(
        block_identifier=block_identifier
    )
    service_registry_address = monitoring_service_proxy.service_registry_address(
        block_identifier=block_identifier
    )

    return DeploymentAddresses(
        token_network_registry_address=token_network_registry_address,
        secret_registry_address=secret_registry_address,
        user_deposit_address=user_deposit_address,
        service_registry_address=service_registry_address,
        monitoring_service_address=monitoring_service_address,
        one_to_n_address=one_to_n_address,
    )


def raiden_bundle_from_contracts_deployment(
    proxy_manager: ProxyManager,
    token_network_registry_address: TokenNetworkRegistryAddress,
    secret_registry_address: SecretRegistryAddress,
) -> RaidenBundle:
    """
    Initialize and setup the contract proxies.

    Depending on the provided contract addresses via the CLI, the routing mode,
    the environment type and the network id try to initialize the proxies.
    Returns the initialized proxies or exits the application with an error if
    there is a problem.

    Also depending on the given arguments populate config with PFS related settings
    """
    contractname_address = [
        (
            "token_network_registry",
            token_network_registry_address,
            proxy_manager.token_network_registry,
        ),
        ("secret_registry", secret_registry_address, proxy_manager.secret_registry),
    ]

    proxies = {}

    for contractname, address, constructor in contractname_address:
        proxy = constructor(address, block_identifier=BLOCK_ID_LATEST)  # type: ignore

        proxies[contractname] = proxy

    # By now these should be set or Raiden aborted
    assert proxies["token_network_registry"], "TokenNetworkRegistry needs to be set"
    assert proxies["secret_registry"], "SecretRegistry needs to be set"

    token_network_registry = proxies["token_network_registry"]
    secret_registry = proxies["secret_registry"]

    return RaidenBundle(
        token_network_registry=token_network_registry, secret_registry=secret_registry
    )


def services_bundle_from_contracts_deployment(
    config: RaidenConfig,
    proxy_manager: ProxyManager,
    routing_mode: RoutingMode,
    deployed_addresses: DeploymentAddresses,
    pathfinding_service_address: str,
    enable_monitoring: bool,
) -> ServicesBundle:
    """
    Initialize and setup the contract proxies.

    Depending on the provided contract addresses via the CLI, the routing mode,
    the environment type and the network id try to initialize the proxies.
    Returns the initialized proxies or exits the application with an error if
    there is a problem.

    Also depending on the given arguments populate config with PFS related settings
    """
    node_chain_id = config.chain_id
    environment_type = config.environment_type

    user_deposit_address = deployed_addresses.user_deposit_address
    service_registry_address = deployed_addresses.service_registry_address
    token_network_registry_address = deployed_addresses.token_network_registry_address

    contractname_address: List[Tuple[str, Address, Callable]] = [
        ("user_deposit", Address(user_deposit_address), proxy_manager.user_deposit)
    ]
    if routing_mode is RoutingMode.PFS:
        contractname_address.append(
            ("service_registry", Address(service_registry_address), proxy_manager.service_registry)
        )
    if enable_monitoring or routing_mode is RoutingMode.PFS:
        contractname_address.append(
            (
                "monitoring_service",
                Address(deployed_addresses.monitoring_service_address),
                proxy_manager.monitoring_service,
            )
        )
        contractname_address.append(
            ("one_to_n", Address(deployed_addresses.one_to_n_address), proxy_manager.one_to_n)
        )

    proxies = {}

    for contractname, address, constructor in contractname_address:
        proxy = constructor(address, block_identifier=BLOCK_ID_LATEST)

        proxies[contractname] = proxy

    if routing_mode is RoutingMode.PFS:
        check_pfs_configuration(pathfinding_service_address=pathfinding_service_address)

        pfs_info = configure_pfs_or_exit(
            pfs_url=pathfinding_service_address,
            routing_mode=routing_mode,
            service_registry=proxies["service_registry"],
            node_chain_id=node_chain_id,
            token_network_registry_address=TokenNetworkRegistryAddress(
                token_network_registry_address
            ),
            pathfinding_max_fee=config.services.pathfinding_max_fee,
        )
        msg = "Eth address of selected pathfinding service is unknown."
        assert pfs_info.payment_address is not None, msg

        # Only check that PFS is registered in production mode
        if environment_type is Environment.PRODUCTION:
            check_pfs_for_production(
                service_registry=proxies["service_registry"], pfs_info=pfs_info
            )

        config.pfs_config = PFSConfig(
            info=pfs_info,
            maximum_fee=config.services.pathfinding_max_fee,
            iou_timeout=config.services.pathfinding_iou_timeout,
            max_paths=config.services.pathfinding_max_paths,
        )
    else:
        config.pfs_config = None

    return ServicesBundle(
        user_deposit=cast(UserDeposit, proxies.get("user_deposit")),
        service_registry=cast(ServiceRegistry, proxies.get("service_registry")),
        monitoring_service=cast(MonitoringService, proxies.get("monitoring_service")),
        one_to_n=cast(OneToN, proxies.get("one_to_n")),
    )
