import sys

import click
import structlog
from eth_utils import denoms
from requests.exceptions import ConnectTimeout, RequestException
from web3 import Web3

from raiden.accounts import AccountManager
from raiden.constants import SQLITE_MIN_REQUIRED_VERSION, Environment, RoutingMode
from raiden.exceptions import EthNodeCommunicationError, EthNodeInterfaceError
from raiden.network.blockchain_service import BlockChainService
from raiden.settings import ETHERSCAN_API, ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE
from raiden.storage.sqlite import assert_sqlite_version
from raiden.ui.sync import wait_for_sync
from raiden.utils import typing
from raiden.utils.ethereum_clients import is_supported_client
from raiden.utils.typing import AddressHex, Dict
from raiden_contracts.constants import GAS_REQUIRED_FOR_ENDPOINT_REGISTER, ID_TO_NETWORKNAME

log = structlog.get_logger(__name__)


def check_sql_version() -> None:
    if not assert_sqlite_version():
        log.error(
            'SQLite3 should be at least version {}'.format(
                '{}.{}.{}'.format(*SQLITE_MIN_REQUIRED_VERSION),
            ),
        )
        sys.exit(1)


def check_ethereum_version(web3: Web3) -> None:
    try:
        node_version = web3.version.node  # pylint: disable=no-member
    except ConnectTimeout:
        raise EthNodeCommunicationError("Couldn't connect to the ethereum node")
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying ethereum node does not have the web3 rpc interface '
            'enabled. Please run it with --rpcapi eth,net,web3,txpool for geth '
            'and --jsonrpc-apis=eth,net,web3,parity for parity.',
        )

    supported, _ = is_supported_client(node_version)
    if not supported:
        click.secho(
            'You need a Byzantium enabled ethereum node. Parity >= 1.7.6 or Geth >= 1.7.2',
            fg='red',
        )
        sys.exit(1)


def check_has_accounts(account_manager: AccountManager) -> None:
    if not account_manager.accounts:
        msg = (
            f'No Ethereum accounts found in the provided keystore directory '
            f'{account_manager.keystore_path}. Please provide a directory '
            f'containing valid ethereum account files.'
        )
        click.secho(msg, fg='red')
        sys.exit(1)


def check_account(account_manager: AccountManager, address_hex: AddressHex) -> None:
    if not account_manager.address_in_keystore(address_hex):
        click.secho(
            f"Account '{address_hex}' could not be found on the system. Aborting ...",
            fg='red',
        )
        sys.exit(1)


def check_network_id(given_network_id: int, web3: Web3) -> None:
    """
    Takes the given network id and checks it against the connected network

    If they don't match, exits the program with an error. If they do adds it
    to the configuration and then returns it and whether it is a known network
    """
    node_network_id = int(web3.version.network)  # pylint: disable=no-member
    known_given_network_id = given_network_id in ID_TO_NETWORKNAME
    known_node_network_id = node_network_id in ID_TO_NETWORKNAME

    if node_network_id != given_network_id:
        if known_given_network_id and known_node_network_id:
            click.secho(
                f"The chosen ethereum network '{ID_TO_NETWORKNAME[given_network_id]}' "
                f"differs from the ethereum client '{ID_TO_NETWORKNAME[node_network_id]}'. "
                "Please update your settings.",
                fg='red',
            )
        else:
            click.secho(
                f"The chosen ethereum network id '{given_network_id}' differs "
                f"from the ethereum client '{node_network_id}'. "
                "Please update your settings.",
                fg='red',
            )
        sys.exit(1)


def check_raiden_environment(
        network_id: int,
        environment_type: Environment,
) -> None:
    not_allowed = (  # for now we only disallow mainnet with test configuration
        network_id == 1 and
        environment_type == Environment.DEVELOPMENT
    )
    if not_allowed:
        click.secho(
            f'The chosen network ({ID_TO_NETWORKNAME[network_id]}) is not a testnet, '
            f'but the "development" environment was selected.\n'
            f'This is not allowed. Please start again with a safe environment setting '
            f'(--environment production).',
            fg='red',
        )
        sys.exit(1)


def check_smart_contract_addresses(
        environment_type: Environment,
        node_network_id: int,
        tokennetwork_registry_contract_address: AddressHex,
        secret_registry_contract_address: AddressHex,
        endpoint_registry_contract_address: AddressHex,
        contracts: Dict[str, AddressHex],
) -> None:
    contract_addresses_given = (
        tokennetwork_registry_contract_address is not None and
        secret_registry_contract_address is not None and
        endpoint_registry_contract_address is not None
    )

    if not contract_addresses_given and not bool(contracts):
        click.secho(
            f"There are no known contract addresses for network id '{node_network_id}'. and "
            f"environment type {environment_type}. Please provide them on the command line or "
            f"in the configuration file.",
            fg='red',
        )
        sys.exit(1)


def check_pfs_configuration(
        routing_mode: RoutingMode,
        environment_type: Environment,
        service_registry: AddressHex,
        pathfinding_service_address: AddressHex,
) -> None:
    if routing_mode == RoutingMode.PFS:
        if environment_type == Environment.PRODUCTION:
            click.secho(
                'Requested production mode and PFS routing mode. This is not supported',
                fg='red',
            )
            sys.exit(1)

        if not service_registry and not pathfinding_service_address:
            click.secho(
                'Requested PFS routing mode but no service registry or no specific pathfinding '
                ' service address is provided. Please provide it via either the '
                '--service-registry-contract-address or the --pathfinding-service-address '
                'argument',
                fg='red',
            )
            sys.exit(1)


def check_synced(blockchain_service: BlockChainService, network_id_is_known: bool) -> None:
    net_id = blockchain_service.network_id
    if not network_id_is_known:
        click.secho(
            f'Your ethereum client is connected to a non-recognized private \n'
            f'network with network-ID {net_id}. Since we can not check if the client \n'
            f'is synced please restart raiden with the --no-sync-check argument.'
            f'\n',
            fg='red',
        )
        sys.exit(1)

    try:
        network = ID_TO_NETWORKNAME[net_id]
    except (EthNodeCommunicationError, RequestException):
        click.secho(
            'Could not determine the network the ethereum node is connected.\n'
            'Because of this there is no way to determine the latest\n'
            'block with an oracle, and the events from the ethereum\n'
            'node cannot be trusted. Giving up.\n',
            fg='red',
        )
        sys.exit(1)

    url = ETHERSCAN_API.format(
        network=network if net_id != 1 else 'api',
        action='eth_blockNumber',
    )
    wait_for_sync(
        blockchain_service,
        url=url,
        tolerance=ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE,
        sleep=3,
    )


def check_discovery_registration_gas(
        blockchain_service: BlockChainService,
        account_address: typing.Address,
) -> None:
    discovery_tx_cost = blockchain_service.client.gas_price() * GAS_REQUIRED_FOR_ENDPOINT_REGISTER
    account_balance = blockchain_service.client.balance(account_address)

    # pylint: disable=no-member
    if discovery_tx_cost > account_balance:
        click.secho(
            'Account has insufficient funds for discovery registration.\n'
            'Needed: {} ETH\n'
            'Available: {} ETH.\n'
            'Please deposit additional funds into this account.'
            .format(discovery_tx_cost / denoms.ether, account_balance / denoms.ether),
            fg='red',
        )
        sys.exit(1)
