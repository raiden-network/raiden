import sys
from typing import Any, Dict, NamedTuple, Optional

import click
from eth_utils import to_canonical_address, to_checksum_address

from raiden.constants import Environment, RoutingMode
from raiden.exceptions import AddressWithoutCode, AddressWrongContract, ContractVersionMismatch
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.pathfinding import configure_pfs_or_exit
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.network.throttle import TokenBucket
from raiden.network.transport import UDPTransport
from raiden.settings import DEVELOPMENT_CONTRACT_VERSION, RED_EYES_CONTRACT_VERSION
from raiden.ui.checks import (
    check_discovery_registration_gas,
    check_pfs_configuration,
    check_raiden_environment,
    check_smart_contract_addresses,
)
from raiden.utils.typing import Address
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
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


def environment_type_to_contracts_version(environment_type: Environment) -> str:
    if environment_type == Environment.DEVELOPMENT:
        contracts_version = DEVELOPMENT_CONTRACT_VERSION
    else:
        contracts_version = RED_EYES_CONTRACT_VERSION

    return contracts_version


def setup_environment(config: Dict[str, Any], environment_type: Environment) -> None:
    """Sets the config depending on the environment type"""
    # interpret the provided string argument
    if environment_type == Environment.PRODUCTION:
        # Safe configuration: restrictions for mainnet apply and matrix rooms have to be private
        config["transport"]["matrix"]["private_rooms"] = True

    config["environment_type"] = environment_type

    print(f"Raiden is running in {environment_type.value.lower()} mode")


def setup_contracts_or_exit(config: Dict[str, Any], network_id: int) -> Dict[str, Any]:
    """Sets the contract deployment data depending on the network id and environment type

    If an invalid combination of network id and environment type is provided, exits
    the program with an error
    """
    environment_type = config["environment_type"]

    check_raiden_environment(network_id, environment_type)

    contracts: Dict[str, Any] = dict()
    contracts_version = environment_type_to_contracts_version(environment_type)

    config["contracts_path"] = contracts_precompiled_path(contracts_version)

    if network_id in ID_TO_NETWORKNAME and ID_TO_NETWORKNAME[network_id] != "smoketest":
        try:
            deployment_data = get_contracts_deployment_info(
                chain_id=network_id, version=contracts_version
            )
        except ValueError:
            return contracts

        contracts = deployment_data["contracts"]

    return contracts


def handle_contract_version_mismatch(mismatch_exception: ContractVersionMismatch) -> None:
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


class Proxies(NamedTuple):
    token_network_registry: TokenNetworkRegistry
    secret_registry: SecretRegistry
    user_deposit: Optional[UserDeposit]
    service_registry: Optional[ServiceRegistry]


def setup_proxies_or_exit(
    config: Dict[str, Any],
    tokennetwork_registry_contract_address: Address,
    secret_registry_contract_address: Address,
    endpoint_registry_contract_address: Address,
    user_deposit_contract_address: Address,
    service_registry_contract_address: Address,
    blockchain_service: BlockChainService,
    contracts: Dict[str, Any],
    routing_mode: RoutingMode,
    pathfinding_service_address: str,
    pathfinding_eth_address: str,
) -> Proxies:
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

    check_smart_contract_addresses(
        environment_type,
        node_network_id,
        tokennetwork_registry_contract_address,
        secret_registry_contract_address,
        endpoint_registry_contract_address,
        contracts,
    )
    try:
        registered_address: Address
        if tokennetwork_registry_contract_address is not None:
            registered_address = Address(tokennetwork_registry_contract_address)
        else:
            registered_address = to_canonical_address(
                contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["address"]
            )
        token_network_registry = blockchain_service.token_network_registry(registered_address)
    except ContractVersionMismatch as e:
        handle_contract_version_mismatch(e)
    except AddressWithoutCode:
        handle_contract_no_code("token network registry", tokennetwork_registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address(
            "token network registry", tokennetwork_registry_contract_address
        )

    try:
        secret_registry = blockchain_service.secret_registry(
            secret_registry_contract_address
            or to_canonical_address(contracts[CONTRACT_SECRET_REGISTRY]["address"])
        )
    except ContractVersionMismatch as e:
        handle_contract_version_mismatch(e)
    except AddressWithoutCode:
        handle_contract_no_code("secret registry", secret_registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address("secret registry", secret_registry_contract_address)

    # If services contracts are provided via the CLI use them instead
    if user_deposit_contract_address is not None:
        contracts[CONTRACT_USER_DEPOSIT] = user_deposit_contract_address
    if service_registry_contract_address is not None:
        contracts[CONTRACT_SERVICE_REGISTRY] = service_registry_contract_address

    user_deposit = None
    should_use_user_deposit = (
        environment_type == Environment.DEVELOPMENT
        and ID_TO_NETWORKNAME.get(node_network_id) != "smoketest"
        and CONTRACT_USER_DEPOSIT in contracts
    )
    if should_use_user_deposit:
        try:
            user_deposit = blockchain_service.user_deposit(
                user_deposit_contract_address
                or to_canonical_address(contracts[CONTRACT_USER_DEPOSIT]["address"])
            )
        except ContractVersionMismatch as e:
            handle_contract_version_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code("user deposit", user_deposit_contract_address)
        except AddressWrongContract:
            handle_contract_wrong_address("user_deposit", user_deposit_contract_address)

    service_registry = None
    if CONTRACT_SERVICE_REGISTRY in contracts or service_registry_contract_address:
        try:
            service_registry = blockchain_service.service_registry(
                service_registry_contract_address
                or to_canonical_address(contracts[CONTRACT_SERVICE_REGISTRY]["address"])
            )
        except ContractVersionMismatch as e:
            handle_contract_version_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code("service registry", service_registry_contract_address)
        except AddressWrongContract:
            handle_contract_wrong_address("secret registry", service_registry_contract_address)

    if routing_mode == RoutingMode.PFS:
        check_pfs_configuration(
            routing_mode, environment_type, service_registry, pathfinding_service_address
        )

        pfs_config = configure_pfs_or_exit(
            pfs_address=pathfinding_service_address,
            pfs_eth_address=pathfinding_eth_address,
            routing_mode=routing_mode,
            service_registry=service_registry,
        )
        msg = "Eth address of selected pathfinding service is unknown."
        assert pfs_config.eth_address is not None, msg
        config["services"]["pathfinding_service_address"] = pfs_config.url
        config["services"]["pathfinding_eth_address"] = pfs_config.eth_address
        config["services"]["pathfinding_fee"] = pfs_config.fee
    else:
        config["services"]["pathfinding_service_address"] = None
        config["services"]["pathfinding_eth_address"] = None

    proxies = Proxies(
        token_network_registry=token_network_registry,
        secret_registry=secret_registry,
        user_deposit=user_deposit,
        service_registry=service_registry,
    )
    return proxies


def setup_udp_or_exit(
    config, blockchain_service, address, contracts, endpoint_registry_contract_address
):
    check_discovery_registration_gas(blockchain_service, address)
    try:
        dicovery_proxy = blockchain_service.discovery(
            endpoint_registry_contract_address
            or to_canonical_address(contracts[CONTRACT_ENDPOINT_REGISTRY]["address"])
        )
        discovery = ContractDiscovery(blockchain_service.node_address, dicovery_proxy)
    except ContractVersionMismatch as e:
        handle_contract_version_mismatch(e)
    except AddressWithoutCode:
        handle_contract_no_code("Endpoint Registry", endpoint_registry_contract_address)
    except AddressWrongContract:
        handle_contract_wrong_address("Endpoint Registry", endpoint_registry_contract_address)

    throttle_policy = TokenBucket(
        config["transport"]["udp"]["throttle_capacity"],
        config["transport"]["udp"]["throttle_fill_rate"],
    )

    transport = UDPTransport(
        address, discovery, config["socket"], throttle_policy, config["transport"]["udp"]
    )

    return transport, discovery
