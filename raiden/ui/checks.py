import sys
from dataclasses import dataclass

import click
import structlog
from web3 import Web3

from raiden.accounts import AccountManager
from raiden.constants import (
    EMPTY_SECRETHASH,
    HIGHEST_SUPPORTED_GETH_VERSION,
    HIGHEST_SUPPORTED_PARITY_VERSION,
    LOWEST_SUPPORTED_GETH_VERSION,
    LOWEST_SUPPORTED_PARITY_VERSION,
    SQLITE_MIN_REQUIRED_VERSION,
    Environment,
)
from raiden.exceptions import EthNodeInterfaceError
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import ETHERSCAN_API, ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE
from raiden.storage.sqlite import assert_sqlite_version
from raiden.ui.sync import wait_for_sync
from raiden.utils.ethereum_clients import is_supported_client
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    BlockSpecification,
    ChainID,
    Dict,
    List,
    MonitoringServiceAddress,
    OneToNAddress,
    Optional,
    ServiceRegistryAddress,
    UserDepositAddress,
)
from raiden_contracts.constants import ID_TO_NETWORKNAME

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ServiceBundleAddresses:
    user_deposit_address: UserDepositAddress
    service_registry_address: ServiceRegistryAddress
    monitoring_service_address: MonitoringServiceAddress
    one_to_n_address: OneToNAddress


def check_sql_version() -> None:
    if not assert_sqlite_version():
        log.error(
            "SQLite3 should be at least version {}".format(
                "{}.{}.{}".format(*SQLITE_MIN_REQUIRED_VERSION)
            )
        )
        sys.exit(1)


def check_ethereum_client_is_supported(web3: Web3) -> None:
    try:
        node_version = web3.version.node  # pylint: disable=no-member
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying ethereum node does not have the web3 rpc interface "
            "enabled. Please run it with --rpcapi eth,net,web3 for geth "
            "and --jsonrpc-apis=eth,net,web3,parity for parity."
        )

    supported, our_client, our_version = is_supported_client(node_version)
    if not supported:
        click.secho(
            f"You need a Byzantium enabled ethereum node. Parity >= "
            f"{LOWEST_SUPPORTED_PARITY_VERSION} <= {HIGHEST_SUPPORTED_PARITY_VERSION}"
            f" or Geth >= {LOWEST_SUPPORTED_GETH_VERSION} <= {HIGHEST_SUPPORTED_GETH_VERSION}"
            f" but you have {our_version} {our_client}",
            fg="red",
        )
        sys.exit(1)


def check_ethereum_has_accounts(account_manager: AccountManager) -> None:
    if not account_manager.accounts:
        msg = (
            f"No Ethereum accounts found in the provided keystore directory "
            f"{account_manager.keystore_path}. Please provide a directory "
            f"containing valid ethereum account files."
        )
        click.secho(msg, fg="red")
        sys.exit(1)


def check_account(account_manager: AccountManager, address_hex: Address) -> None:
    if not account_manager.address_in_keystore(to_checksum_address(address_hex)):
        click.secho(
            f"Account '{address_hex}' could not be found on the system. Aborting ...", fg="red"
        )
        sys.exit(1)


def check_ethereum_confirmed_block_is_not_pruned(
    jsonrpc_client: JSONRPCClient, secret_registry: SecretRegistry, confirmation_blocks: int
) -> None:
    """Checks the Ethereum client is not pruning data too aggressively, because
    in some circunstances it is necessary for a node to fetch additional data
    from the smart contract.
    """
    unconfirmed_block_number = jsonrpc_client.block_number()

    # This is a small error margin. It is possible during normal operation for:
    #
    # - AlarmTask sees a new block and calls RaidenService._callback_new_block
    # - The service gets the current latest block number and computes the
    #   confirmed block number.
    # - The service fetches every filter, this can take a while.
    # - While the above is happening, it is possible for a `few_blocks` to be
    #   mined.
    # - The decode function is called, and tries to access what it thinks is
    #   the latest_confirmed_block, but it is in reality `few_blocks` older.
    #
    # This value bellow is the expected drift, that allows the decode function
    # mentioned above to work properly.
    maximum_delay_to_process_a_block = 2

    minimum_available_history = confirmation_blocks + maximum_delay_to_process_a_block
    target_confirmed_block = unconfirmed_block_number - minimum_available_history

    try:
        # Using the secret registry is arbitrary, any proxy with an `eth_call`
        # would work here.
        secret_registry.get_secret_registration_block_by_secrethash(
            EMPTY_SECRETHASH, block_identifier=target_confirmed_block
        )
    except ValueError:
        # If this exception is raised the Ethereum node is too aggressive with
        # the block pruning.
        click.secho(
            f"The ethereum client does not have the necessary data available. "
            f"The client can not operate because the prunning strategy is too "
            f"agressive. Please make sure that at very minimum "
            f"{minimum_available_history} blocks of history are available.",
            fg="red",
        )
        sys.exit(1)


def check_ethereum_network_id(given_network_id: ChainID, web3: Web3) -> None:
    """
    Takes the given network id and checks it against the connected network

    If they don't match, exits the program with an error. If they do adds it
    to the configuration and then returns it and whether it is a known network
    """
    node_network_id = ChainID(int(web3.version.network))  # pylint: disable=no-member

    if node_network_id != given_network_id:
        given_name = ID_TO_NETWORKNAME.get(given_network_id)
        network_name = ID_TO_NETWORKNAME.get(node_network_id)

        given_description = f'{given_name or "Unknown"} (id {given_network_id})'
        network_description = f'{network_name or "Unknown"} (id {node_network_id})'

        # TODO: fix cyclic import
        from raiden.ui.cli import ETH_NETWORKID_OPTION

        msg = (
            f"The configured network {given_description} differs "
            f"from the Ethereum client's network {network_description}. The "
            f"network_id can be configured using the flag {ETH_NETWORKID_OPTION}"
            f"Please check your settings."
        )
        click.secho(msg, fg="red")
        sys.exit(1)


def check_raiden_environment(network_id: ChainID, environment_type: Environment) -> None:
    warn = (  # mainnet --development is only for tests
        network_id == 1 and environment_type == Environment.DEVELOPMENT
    )
    if warn:
        click.secho(
            f"The chosen network ({ID_TO_NETWORKNAME[network_id]}) is not a testnet, "
            f'but the "development" environment was selected.\n'
            f"This crashes the node often. Please start again with a safe environment setting "
            f"(--environment production).",
            fg="red",
        )


def check_deployed_contracts_data(
    environment_type: Environment,
    node_network_id: ChainID,
    contracts: Dict[str, Address],
    required_contracts: List[str],
) -> None:
    """ This function only checks if all necessary contracts are indeed in the deployment JSON
    from Raiden Contracts. It does not check anything else, especially not if those contracts
    are consistent or in fact Raiden contracts.

    """
    for name in required_contracts:
        if name not in contracts:
            click.secho(
                f"There are no known contract addresses for network id '{node_network_id}'. and "
                f"environment type {environment_type}.",
                fg="red",
            )
            sys.exit(1)


def check_pfs_configuration(
    service_registry: Optional[ServiceRegistry], pathfinding_service_address: str
) -> None:
    if not service_registry and not pathfinding_service_address:
        click.secho(
            "Requested PFS routing mode but no service registry or no specific pathfinding "
            " service address is provided. Please provide it via either the "
            "--service-registry-contract-address or the --pathfinding-service-address "
            "argument",
            fg="red",
        )
        sys.exit(1)


def check_synced(proxy_manager: ProxyManager) -> None:
    network_id = ChainID(int(proxy_manager.client.web3.version.network))
    network_name = ID_TO_NETWORKNAME.get(network_id)

    if network_name is None:
        msg = (
            f"Your ethereum client is connected to a non-recognized private "
            f"network with network-ID {network_id}. Since we can not check if the "
            f"client is synced please restart raiden with the --no-sync-check "
            f"argument."
        )
        click.secho(msg, fg="red")
        sys.exit(1)

    url = ETHERSCAN_API.format(
        network=network_name if network_id != 1 else "api", action="eth_blockNumber"
    )
    wait_for_sync(proxy_manager, url=url, tolerance=ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE, sleep=3)


def check_user_deposit_deps_consistency(
    proxy_manager: ProxyManager,
    service_bundle_addresses: ServiceBundleAddresses,
    block_identifier: BlockSpecification,
) -> None:
    user_deposit_address = service_bundle_addresses.user_deposit_address
    user_deposit = proxy_manager.user_deposit(user_deposit_address)
    token_address = user_deposit.token_address(block_identifier)

    msc_address = service_bundle_addresses.monitoring_service_address
    one_to_n_address = service_bundle_addresses.one_to_n_address
    service_registry_address = service_bundle_addresses.service_registry_address

    monitoring_service_proxy = proxy_manager.monitoring_service(msc_address)
    one_to_n_proxy = proxy_manager.one_to_n(one_to_n_address)
    service_registry_proxy = proxy_manager.service_registry(service_registry_address)

    token_address_matches_monitoring_service = (
        token_address == monitoring_service_proxy.token_address(block_identifier)
    )
    if not token_address_matches_monitoring_service:
        msg = (
            f"The token used in the provided user deposit contract "
            f"{user_deposit_address} does not match the one in the "
            f"MonitoringService contract {msc_address}."
        )
        click.secho(msg, fg="red")
        sys.exit(1)

    token_address_matches_one_to_n = token_address == one_to_n_proxy.token_address(
        block_identifier
    )
    if not token_address_matches_one_to_n:
        msg = (
            f"The token used in the provided user deposit contract "
            f"{user_deposit_address} does not match the one in the OneToN "
            f"service contract {msc_address}."
        )
        click.secho(msg, fg="red")
        sys.exit(1)

    token_address_matches_service_registry = token_address == service_registry_proxy.token_address(
        block_identifier
    )
    if not token_address_matches_service_registry:
        msg = (
            f"The token used in the provided user deposit contract "
            f"{user_deposit_address} does not match the one in the ServiceRegistry "
            f"contract {msc_address}."
        )
        click.secho(msg, fg="red")
        sys.exit(1)
