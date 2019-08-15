import sys
from typing import Any, Dict, NamedTuple, Optional

import click
from eth_utils import to_canonical_address, to_checksum_address

from raiden.constants import Environment, RoutingMode
from raiden.exceptions import AddressWithoutCode, AddressWrongContract, ContractCodeMismatch
from raiden.network.blockchain_service import BlockChainService
from raiden.network.pathfinding import PFSConfig, check_pfs_for_production, configure_pfs_or_exit
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.settings import DEVELOPMENT_CONTRACT_VERSION, PRODUCTION_CONTRACT_VERSION
from raiden.ui.checks import (
    check_pfs_configuration,
    check_raiden_environment,
    check_smart_contract_addresses,
)
from raiden.utils.typing import Address, ChainID, TokenNetworkRegistryAddress
from raiden_contracts.constants import (
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
        contracts_version = PRODUCTION_CONTRACT_VERSION

    return contracts_version


def setup_environment(config: Dict[str, Any], environment_type: Environment) -> None:
    """Sets the config depending on the environment type"""
    # interpret the provided string argument
    if environment_type == Environment.PRODUCTION:
        # Safe configuration: restrictions for mainnet apply and matrix rooms have to be private
        config["transport"]["matrix"]["private_rooms"] = True

    config["environment_type"] = environment_type

    print(f"Raiden is running in {environment_type.value.lower()} mode")


def setup_contracts_or_exit(config: Dict[str, Any], network_id: ChainID) -> Dict[str, Any]:
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
        deployment_data = get_contracts_deployment_info(
            chain_id=network_id, version=contracts_version
        )
        if not deployment_data:
            return contracts

        contracts = deployment_data["contracts"]

    return contracts


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


class Proxies(NamedTuple):
    token_network_registry: TokenNetworkRegistry
    secret_registry: SecretRegistry
    user_deposit: Optional[UserDeposit]
    service_registry: Optional[ServiceRegistry]


def setup_proxies_or_exit(
    config: Dict[str, Any],
    tokennetwork_registry_contract_address: TokenNetworkRegistryAddress,
    secret_registry_contract_address: Address,
    user_deposit_contract_address: Address,
    service_registry_contract_address: Address,
    blockchain_service: BlockChainService,
    contracts: Dict[str, Any],
    routing_mode: RoutingMode,
    pathfinding_service_address: str,
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
        environment_type=environment_type,
        node_network_id=node_network_id,
        tokennetwork_registry_contract_address=tokennetwork_registry_contract_address,
        secret_registry_contract_address=secret_registry_contract_address,
        contracts=contracts,
    )

    token_network_registry = None
    try:
        if tokennetwork_registry_contract_address is not None:
            registered_address = tokennetwork_registry_contract_address
        else:
            registered_address = to_canonical_address(
                contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["address"]
            )
        token_network_registry = blockchain_service.token_network_registry(registered_address)
    except ContractCodeMismatch as e:
        handle_contract_code_mismatch(e)
    except AddressWithoutCode:
        handle_contract_no_code(
            "token network registry", Address(tokennetwork_registry_contract_address)
        )
    except AddressWrongContract:
        handle_contract_wrong_address(
            "token network registry", Address(tokennetwork_registry_contract_address)
        )

    secret_registry = None
    try:
        secret_registry = blockchain_service.secret_registry(
            secret_registry_contract_address
            or to_canonical_address(contracts[CONTRACT_SECRET_REGISTRY]["address"])
        )
    except ContractCodeMismatch as e:
        handle_contract_code_mismatch(e)
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
        except ContractCodeMismatch as e:
            handle_contract_code_mismatch(e)
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
        except ContractCodeMismatch as e:
            handle_contract_code_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code("service registry", service_registry_contract_address)
        except AddressWrongContract:
            handle_contract_wrong_address("secret registry", service_registry_contract_address)

    # By now these should be set or Raiden aborted
    assert token_network_registry, "TokenNetworkRegistry needs to be set"
    assert secret_registry, "SecretRegistry needs to be set"

    if routing_mode == RoutingMode.PFS:
        check_pfs_configuration(
            service_registry=service_registry,
            pathfinding_service_address=pathfinding_service_address,
        )

        pfs_info = configure_pfs_or_exit(
            pfs_url=pathfinding_service_address,
            routing_mode=routing_mode,
            service_registry=service_registry,
            node_network_id=node_network_id,
            token_network_registry_address=token_network_registry.address,
            pathfinding_max_fee=config["services"]["pathfinding_max_fee"],
        )
        msg = "Eth address of selected pathfinding service is unknown."
        assert pfs_info.payment_address is not None, msg

        # Only check that PFS is registered in production mode
        if environment_type == Environment.PRODUCTION:
            check_pfs_for_production(service_registry=service_registry, pfs_info=pfs_info)

        config["pfs_config"] = PFSConfig(
            info=pfs_info,
            maximum_fee=config["services"]["pathfinding_max_fee"],
            iou_timeout=config["services"]["pathfinding_iou_timeout"],
            max_paths=config["services"]["pathfinding_max_paths"],
        )
    else:
        config["pfs_config"] = None

    proxies = Proxies(
        token_network_registry=token_network_registry,
        secret_registry=secret_registry,
        user_deposit=user_deposit,
        service_registry=service_registry,
    )
    return proxies
