import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional

import click
from eth_utils import to_canonical_address

from raiden.constants import NULL_ADDRESS_BYTES, Environment, RoutingMode
from raiden.exceptions import AddressWithoutCode, AddressWrongContract, ContractCodeMismatch
from raiden.network.pathfinding import PFSConfig, check_pfs_for_production, configure_pfs_or_exit
from raiden.network.proxies.monitoring_service import MonitoringService
from raiden.network.proxies.one_to_n import OneToN
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.settings import RAIDEN_CONTRACT_VERSION
from raiden.ui.checks import (
    ServiceBundleAddresses,
    check_deployed_contracts_data,
    check_pfs_configuration,
    check_raiden_environment,
    check_user_deposit_deps_consistency,
)
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    BlockSpecification,
    Callable,
    ChainID,
    List,
    TokenNetworkRegistryAddress,
    Tuple,
    UserDepositAddress,
)
from raiden_contracts.constants import (
    CONTRACT_MONITORING_SERVICE,
    CONTRACT_ONE_TO_N,
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    CONTRACT_USER_DEPOSIT,
    ID_TO_NETWORKNAME,
)
from raiden_contracts.contract_manager import (
    contracts_precompiled_path,
    get_contracts_deployment_info,
)


@dataclass(frozen=True)
class RaidenBundle:
    token_network_registry: TokenNetworkRegistry
    secret_registry: SecretRegistry


@dataclass(frozen=True)
class ServicesBundle:
    user_deposit: Optional[UserDeposit]
    service_registry: Optional[ServiceRegistry]
    monitoring_service: Optional[MonitoringService]
    one_to_n: Optional[OneToN]


def setup_environment(config: Dict[str, Any], environment_type: Environment) -> None:
    """Sets the config depending on the environment type"""
    # interpret the provided string argument
    config["environment_type"] = environment_type

    print(f"Raiden is running in {environment_type.value.lower()} mode")


def load_deployed_contracts_data(config: Dict[str, Any], network_id: ChainID) -> Dict[str, Any]:
    """Sets the contract deployment data depending on the network id and environment type

    If an invalid combination of network id and environment type is provided, exits
    the program with an error
    """
    environment_type = config["environment_type"]

    check_raiden_environment(network_id, environment_type)

    deployed_contracts_data: Dict[str, Any] = dict()
    contracts_version = RAIDEN_CONTRACT_VERSION

    config["contracts_path"] = contracts_precompiled_path(contracts_version)

    if network_id in ID_TO_NETWORKNAME and ID_TO_NETWORKNAME[network_id] != "smoketest":
        deployment_data = get_contracts_deployment_info(
            chain_id=network_id, version=contracts_version
        )
        if not deployment_data:
            return deployed_contracts_data

        deployed_contracts_data = deployment_data["contracts"]

    return deployed_contracts_data


def handle_contract_code_mismatch(mismatch_exception: ContractCodeMismatch) -> None:
    click.secho(f"{str(mismatch_exception)}. Please update your Raiden installation.", fg="red")
    sys.exit(1)


def handle_contract_no_code(name: str, address: Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(f"Error: Provided {name} {hex_addr} contract does not contain code", fg="red")
    sys.exit(1)


def handle_contract_wrong_address(name: str, address: Address) -> None:
    hex_addr = to_checksum_address(address)
    click.secho(
        f"Error: Provided address {hex_addr} for {name} contract"
        " does not contain expected code.",
        fg="red",
    )
    sys.exit(1)


def raiden_bundle_from_contracts_deployment(
    config: Dict[str, Any], proxy_manager: ProxyManager, contracts: Dict[str, Any]
) -> RaidenBundle:
    """
    Initialize and setup the contract proxies.

    Depending on the provided contract addresses via the CLI, the routing mode,
    the environment type and the network id try to initialize the proxies.
    Returns the initialized proxies or exits the application with an error if
    there is a problem.

    Also depending on the given arguments populate config with PFS related settings
    """
    node_network_id = config["chain_id"]
    environment_type = config["environment_type"]

    core_contract_names = [CONTRACT_TOKEN_NETWORK_REGISTRY, CONTRACT_SECRET_REGISTRY]
    check_deployed_contracts_data(
        node_network_id=node_network_id,
        environment_type=environment_type,
        contracts=contracts,
        required_contracts=core_contract_names,
    )

    token_network_registry_address = to_canonical_address(
        contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["address"]
    )
    secret_registry_address = to_canonical_address(contracts[CONTRACT_SECRET_REGISTRY]["address"])

    contractname_address = [
        (
            "token_network_registry",
            token_network_registry_address,
            proxy_manager.token_network_registry,
        ),
        ("secret_registry", secret_registry_address, proxy_manager.secret_registry),
    ]

    proxies = dict()

    for contractname, address, constructor in contractname_address:
        try:
            proxy = constructor(address)  # type: ignore
        except ContractCodeMismatch as e:
            handle_contract_code_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code(contractname, address)
        except AddressWrongContract:
            handle_contract_wrong_address(contractname, address)

        proxies[contractname] = proxy

    # By now these should be set or Raiden aborted
    assert proxies["token_network_registry"], "TokenNetworkRegistry needs to be set"
    assert proxies["secret_registry"], "SecretRegistry needs to be set"

    token_network_registry = proxies["token_network_registry"]
    secret_registry = proxies["secret_registry"]

    return RaidenBundle(
        token_network_registry=token_network_registry, secret_registry=secret_registry
    )


def load_service_addresses(
    proxy_manager: ProxyManager,
    user_deposit_address: UserDepositAddress,
    block_identifier: BlockSpecification,
) -> ServiceBundleAddresses:
    """Given a user deposit address, this function returns the list of contract addresses
    which are used as services which are bound to the user deposit contract deployed.
    """
    block_identifier = "latest"
    user_deposit = proxy_manager.user_deposit(user_deposit_address)
    msc_address = user_deposit.msc_address(block_identifier)
    one_to_n_address = user_deposit.one_to_n_address(block_identifier)

    monitoring_service_proxy = proxy_manager.monitoring_service(msc_address)

    service_registry_address = monitoring_service_proxy.service_registry_address(block_identifier)

    return ServiceBundleAddresses(
        user_deposit_address=user_deposit_address,
        service_registry_address=service_registry_address,
        monitoring_service_address=msc_address,
        one_to_n_address=one_to_n_address,
    )


def services_bundle_from_contracts_deployment(
    config: Dict[str, Any],
    proxy_manager: ProxyManager,
    contracts: Dict[str, Any],
    routing_mode: RoutingMode,
    user_deposit_contract_address: Optional[UserDepositAddress],
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
    node_network_id = config["chain_id"]
    environment_type = config["environment_type"]

    if user_deposit_contract_address is None:
        user_deposit_contract_address = contracts[CONTRACT_USER_DEPOSIT]["address"]

    service_bundle_addresses = load_service_addresses(
        proxy_manager=proxy_manager,
        user_deposit_address=user_deposit_contract_address,
        block_identifier="latest",
    )

    services_contracts_map = {
        "monitoring_service_address": CONTRACT_MONITORING_SERVICE,
        "user_deposit_address": CONTRACT_USER_DEPOSIT,
        "one_to_n_address": CONTRACT_ONE_TO_N,
        "service_registry_address": CONTRACT_SERVICE_REGISTRY,
    }
    # Filter out contracts from the `contracts` map which we've been unable
    # to find an address for.
    for address_member, contract_name in services_contracts_map.items():
        if getattr(service_bundle_addresses, address_member) == NULL_ADDRESS_BYTES:
            del contracts[contract_name]

    # If the above step ends up removing any of the required services
    # contracts, the following step will exit.
    check_deployed_contracts_data(
        node_network_id=node_network_id,
        environment_type=environment_type,
        contracts=contracts,
        required_contracts=list(services_contracts_map.values()),
    )

    check_user_deposit_deps_consistency(
        proxy_manager=proxy_manager,
        service_bundle_addresses=service_bundle_addresses,
        block_identifier="latest",
    )

    token_network_registry_address = to_canonical_address(
        contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["address"]
    )
    service_registry_contract_address = to_canonical_address(
        contracts[CONTRACT_SERVICE_REGISTRY]["address"]
    )
    if not user_deposit_contract_address:
        user_deposit_contract_address = UserDepositAddress(
            to_canonical_address(contracts[CONTRACT_USER_DEPOSIT]["address"])
        )

    contractname_address: List[Tuple[str, Address, Callable]] = []
    if routing_mode == RoutingMode.PFS:
        contractname_address.append(
            (
                "service_registry",
                Address(service_registry_contract_address),
                proxy_manager.service_registry,
            )
        )
    if enable_monitoring or routing_mode == RoutingMode.PFS:
        contractname_address.append(
            ("user_deposit", Address(user_deposit_contract_address), proxy_manager.user_deposit)
        )
        contractname_address.append(
            (
                "monitoring_service",
                Address(service_bundle_addresses.monitoring_service_address),
                proxy_manager.monitoring_service,
            )
        )
        contractname_address.append(
            (
                "one_to_n",
                Address(service_bundle_addresses.one_to_n_address),
                proxy_manager.one_to_n,
            )
        )

    proxies = dict()

    for contractname, address, constructor in contractname_address:
        try:
            proxy = constructor(address)
        except ContractCodeMismatch as e:
            handle_contract_code_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code(contractname, address)
        except AddressWrongContract:
            handle_contract_wrong_address(contractname, address)

        proxies[contractname] = proxy

    if routing_mode == RoutingMode.PFS:
        check_pfs_configuration(
            service_registry=proxies["service_registry"],
            pathfinding_service_address=pathfinding_service_address,
        )

        pfs_info = configure_pfs_or_exit(
            pfs_url=pathfinding_service_address,
            routing_mode=routing_mode,
            service_registry=proxies["service_registry"],
            node_network_id=node_network_id,
            token_network_registry_address=TokenNetworkRegistryAddress(
                token_network_registry_address
            ),
            pathfinding_max_fee=config["services"]["pathfinding_max_fee"],
        )
        msg = "Eth address of selected pathfinding service is unknown."
        assert pfs_info.payment_address is not None, msg

        # Only check that PFS is registered in production mode
        if environment_type == Environment.PRODUCTION:
            check_pfs_for_production(
                service_registry=proxies["service_registry"], pfs_info=pfs_info
            )

        config["pfs_config"] = PFSConfig(
            info=pfs_info,
            maximum_fee=config["services"].pathfinding_max_fee,
            iou_timeout=config["services"].pathfinding_iou_timeout,
            max_paths=config["services"].pathfinding_max_paths,
        )
    else:
        config["pfs_config"] = None

    return ServicesBundle(
        user_deposit=proxies["user_deposit"],
        service_registry=proxies["service_registry"],
        monitoring_service=proxies["monitoring_service"],
        one_to_n=proxies["one_to_n"],
    )
