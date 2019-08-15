import sys

import click
import structlog
from eth_utils import to_checksum_address
from requests.exceptions import ConnectTimeout
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
from raiden.exceptions import EthNodeCommunicationError, EthNodeInterfaceError
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import ETHERSCAN_API, ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE
from raiden.storage.sqlite import assert_sqlite_version
from raiden.ui.sync import wait_for_sync
from raiden.utils.ethereum_clients import is_supported_client
from raiden.utils.typing import Address, ChainID, Dict, Optional, TokenNetworkRegistryAddress
from raiden_contracts.constants import ID_TO_NETWORKNAME

log = structlog.get_logger(__name__)


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
    except ConnectTimeout:
        raise EthNodeCommunicationError("Couldn't connect to the ethereum node")
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying ethereum node does not have the web3 rpc interface "
            "enabled. Please run it with --rpcapi eth,net,web3,txpool for geth "
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

        msg = (
            f"The configured network {given_description} differs "
            f"from the Ethereum client's network {network_description}. "
            f"Please check your settings."
        )
        click.secho(msg, fg="red")
        sys.exit(1)


def check_raiden_environment(network_id: ChainID, environment_type: Environment) -> None:
    not_allowed = (  # for now we only disallow mainnet with test configuration
        network_id == 1 and environment_type == Environment.DEVELOPMENT
    )
    if not_allowed:
        click.secho(
            f"The chosen network ({ID_TO_NETWORKNAME[network_id]}) is not a testnet, "
            f'but the "development" environment was selected.\n'
            f"This is not allowed. Please start again with a safe environment setting "
            f"(--environment production).",
            fg="red",
        )
        sys.exit(1)


def check_smart_contract_addresses(
    environment_type: Environment,
    node_network_id: ChainID,
    tokennetwork_registry_contract_address: TokenNetworkRegistryAddress,
    secret_registry_contract_address: Address,
    contracts: Dict[str, Address],
) -> None:
    contract_addresses_given = (
        tokennetwork_registry_contract_address is not None
        and secret_registry_contract_address is not None
    )

    if not contract_addresses_given and not bool(contracts):
        click.secho(
            f"There are no known contract addresses for network id '{node_network_id}'. and "
            f"environment type {environment_type}. Please provide them on the command line or "
            f"in the configuration file.",
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


def check_synced(blockchain_service: BlockChainService) -> None:
    network_id = ChainID(int(blockchain_service.client.web3.version.network))
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
    wait_for_sync(
        blockchain_service, url=url, tolerance=ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE, sleep=3
    )
