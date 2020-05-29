from dataclasses import dataclass

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
from raiden.exceptions import EthNodeInterfaceError, RaidenError
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.rpc.client import JSONRPCClient
from raiden.settings import ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE
from raiden.storage.sqlite import assert_sqlite_version
from raiden.ui.sync import wait_for_sync
from raiden.utils.ethereum_clients import is_supported_client
from raiden.utils.typing import (
    Address,
    BlockNumber,
    ChainID,
    Dict,
    List,
    MonitoringServiceAddress,
    OneToNAddress,
    SecretRegistryAddress,
    ServiceRegistryAddress,
    TokenNetworkRegistryAddress,
    UserDepositAddress,
)
from raiden_contracts.constants import ID_TO_CHAINNAME

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class DeploymentAddresses:
    token_network_registry_address: TokenNetworkRegistryAddress
    secret_registry_address: SecretRegistryAddress
    user_deposit_address: UserDepositAddress
    service_registry_address: ServiceRegistryAddress
    monitoring_service_address: MonitoringServiceAddress
    one_to_n_address: OneToNAddress


def check_sql_version() -> None:
    if not assert_sqlite_version():
        version = "{}.{}.{}".format(*SQLITE_MIN_REQUIRED_VERSION)
        raise RaidenError(f"SQLite3 should be at least version {version}")


def check_ethereum_client_is_supported(web3: Web3) -> None:
    try:
        node_version = web3.clientVersion
    except ValueError:
        raise EthNodeInterfaceError(
            "The underlying ethereum node does not have the web3 rpc interface "
            "enabled. Please run it with --rpcapi eth,net,web3 for geth "
            "and --jsonrpc-apis=eth,net,web3,parity for parity."
        )

    supported, our_client, our_version = is_supported_client(node_version)
    if not supported:
        raise RaidenError(
            f"You need a Byzantium enabled ethereum node. Parity >= "
            f"{LOWEST_SUPPORTED_PARITY_VERSION} <= {HIGHEST_SUPPORTED_PARITY_VERSION}"
            f" or Geth >= {LOWEST_SUPPORTED_GETH_VERSION} <= {HIGHEST_SUPPORTED_GETH_VERSION}"
            f" but you have {our_version} {our_client}"
        )


def check_ethereum_has_accounts(account_manager: AccountManager) -> None:
    if not account_manager.accounts:
        raise RaidenError(
            f"No Ethereum accounts found in the provided keystore directory "
            f"{account_manager.keystore_path}. Please provide a directory "
            f"containing valid ethereum account files."
        )


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
    # This value below is the expected drift, that allows the decode function
    # mentioned above to work properly.
    maximum_delay_to_process_a_block = 2

    minimum_available_history = confirmation_blocks + maximum_delay_to_process_a_block
    target_confirmed_block = BlockNumber(unconfirmed_block_number - minimum_available_history)

    try:
        # Using the secret registry is arbitrary, any proxy with an `eth_call`
        # would work here.
        secret_registry.get_secret_registration_block_by_secrethash(
            EMPTY_SECRETHASH, block_identifier=target_confirmed_block
        )
    except ValueError:
        # If this exception is raised the Ethereum node is too aggressive with
        # the block pruning.
        raise RaidenError(
            f"The ethereum client does not have the necessary data available. "
            f"The client can not operate because the prunning strategy is too "
            f"agressive. Please make sure that at very minimum "
            f"{minimum_available_history} blocks of history are available."
        )


def check_ethereum_network_id(given_network_id: ChainID, web3: Web3) -> None:
    """
    Takes the given network id and checks it against the connected network

    If they don't match, exits the program with an error. If they do adds it
    to the configuration and then returns it and whether it is a known network
    """
    node_network_id = ChainID(web3.eth.chainId)

    if node_network_id != given_network_id:
        given_name = ID_TO_CHAINNAME.get(given_network_id)
        network_name = ID_TO_CHAINNAME.get(node_network_id)

        given_description = f'{given_name or "Unknown"} (id {given_network_id})'
        network_description = f'{network_name or "Unknown"} (id {node_network_id})'

        # TODO: fix cyclic import
        from raiden.ui.cli import ETH_NETWORKID_OPTION

        raise RaidenError(
            f"The configured network {given_description} differs "
            f"from the Ethereum client's network {network_description}. The "
            f"network_id can be configured using the flag {ETH_NETWORKID_OPTION}"
            f"Please check your settings."
        )


def check_raiden_environment(network_id: ChainID, environment_type: Environment) -> None:
    warn = (  # mainnet --development is only for tests
        network_id == 1 and environment_type == Environment.DEVELOPMENT
    )
    if warn:
        raise RaidenError(
            f"The chosen network ({ID_TO_CHAINNAME[network_id]}) is not a testnet, "
            f'but the "development" environment was selected.\n'
            f"This crashes the node often. Please start again with a safe environment setting "
            f"(--environment-type production)."
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
            raise RaidenError(
                f"There are no known contract addresses for network id '{node_network_id}'. and "
                f"environment type {environment_type} for contract {name}."
            )


def check_pfs_configuration(pathfinding_service_address: str) -> None:
    if not pathfinding_service_address:
        raise RaidenError(
            "Requested PFS routing mode but no specific pathfinding "
            "service address is provided. Please provide it via the "
            "--pathfinding-service-address argument"
        )


def check_synced(rpc_client: JSONRPCClient) -> None:
    wait_for_sync(rpc_client=rpc_client, tolerance=ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE, sleep=3)
