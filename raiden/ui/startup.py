import sys
from typing import Any, Dict, NamedTuple, Optional

import click
from eth_utils import to_canonical_address

from raiden.constants import Environment, RoutingMode
from raiden.exceptions import AddressWithoutCode, AddressWrongContract, ContractCodeMismatch
from raiden.network.pathfinding import PFSConfig, check_pfs_for_production, configure_pfs_or_exit
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.settings import RAIDEN_CONTRACT_VERSION
from raiden.ui.checks import (
    check_pfs_configuration,
    check_raiden_environment,
    check_deployed_contracts_data,
)
from raiden.utils.formatting import to_checksum_address
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

        deployed_contracts_data = deployment_data["deployed_contracts_data"]

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


class Proxies(NamedTuple):
    token_network_registry: TokenNetworkRegistry
    secret_registry: SecretRegistry
    user_deposit: Optional[UserDeposit]
    service_registry: Optional[ServiceRegistry]


def proxies_from_contracts_deployment(
    config: Dict[str, Any],
    proxy_manager: ProxyManager,
    contracts: Dict[str, Any],
    routing_mode: RoutingMode,
    pathfinding_service_address: str,
    enable_monitoring: bool,
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

    token_network_registry = None
    token_network_registry_address = to_canonical_address(
        contracts[CONTRACT_TOKEN_NETWORK_REGISTRY]["address"]
    )
    secret_registry_address = to_canonical_address(contracts[CONTRACT_SECRET_REGISTRY]["address"])
    user_deposit_contract_address = to_canonical_address(contracts[CONTRACT_USER_DEPOSIT]["address"])
    service_registry_contract_address = to_canonical_address(contracts[CONTRACT_SERVICE_REGISTRY]["address"])

    contractname_address = [
        ("token network registry", token_network_registry_address, proxy_manager.token_network_registry),
        ("secret registry", secret_registry_address, proxy_manager.secret_registry),


    ]
    if routing_mode == RoutingMode.PFS:
        contractname_address.append(("service registry", service_registry_contract_address, proxy_manager.service_registry))
    if enable_monitoring or routing_mode == RoutingMode.PFS:
        contractname_address.append(("user_deposit", user_deposit_contract_address, proxy_manager.user_deposit))

    proxies = dict()

    for contractname, address, constructor in contractname_address:

        try:
            proxy = constructor(address)
        except ContractCodeMismatch as e:
            handle_contract_code_mismatch(e)
        except AddressWithoutCode:
            handle_contract_no_code(
                contractname, address
            )
        except AddressWrongContract:
            handle_contract_wrong_address(
                contractname, address
        )

        proxies[contractname] = proxy

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
            pathfinding_max_fee=config["services"].pathfinding_max_fee,
        )
        msg = "Eth address of selected pathfinding service is unknown."
        assert pfs_info.payment_address is not None, msg

        # Only check that PFS is registered in production mode
        if environment_type == Environment.PRODUCTION:
            check_pfs_for_production(service_registry=service_registry, pfs_info=pfs_info)

        config["pfs_config"] = PFSConfig(
            info=pfs_info,
            maximum_fee=config["services"].pathfinding_max_fee,
            iou_timeout=config["services"].pathfinding_iou_timeout,
            max_paths=config["services"].pathfinding_max_paths,
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
