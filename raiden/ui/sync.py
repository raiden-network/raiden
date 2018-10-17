import sys
from itertools import count

import click
import gevent
import requests
from eth_utils import denoms, to_int
from requests.exceptions import RequestException

from raiden.exceptions import EthNodeCommunicationError
from raiden.network.blockchain_service import BlockChainService
from raiden.settings import ETHERSCAN_API, ORACLE_BLOCKNUMBER_DRIFT_TOLERANCE
from raiden.utils import typing
from raiden_contracts.constants import GAS_REQUIRED_FOR_ENDPOINT_REGISTER, ID_TO_NETWORKNAME


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


def etherscan_query_with_retries(
        url: str,
        sleep: float,
        retries: int = 3,
) -> int:
    for _ in range(retries - 1):
        try:
            etherscan_block = to_int(hexstr=requests.get(url).json()['result'])
        except (RequestException, ValueError, KeyError):
            gevent.sleep(sleep)
        else:
            return etherscan_block

    etherscan_block = to_int(hexstr=requests.get(url).json()['result'])
    return etherscan_block


def wait_for_sync_etherscan(
        blockchain_service: BlockChainService,
        url: str,
        tolerance: int,
        sleep: float,
) -> None:
    local_block = blockchain_service.client.block_number()
    etherscan_block = etherscan_query_with_retries(url, sleep)
    syncing_str = '\rSyncing ... Current: {} / Target: ~{}'

    if local_block >= etherscan_block - tolerance:
        return

    print('Waiting for the ethereum node to synchronize. [Use ^C to exit]')
    print(syncing_str.format(local_block, etherscan_block), end='')

    for i in count():
        sys.stdout.flush()
        gevent.sleep(sleep)
        local_block = blockchain_service.client.block_number()

        # update the oracle block number sparsely to not spam the server
        if local_block >= etherscan_block or i % 50 == 0:
            etherscan_block = etherscan_query_with_retries(url, sleep)

            if local_block >= etherscan_block - tolerance:
                return

        print(syncing_str.format(local_block, etherscan_block), end='')

    # add a newline so that the next print will start have it's own line
    print('')


def wait_for_sync_rpc_api(
        blockchain_service: BlockChainService,
        sleep: float,
) -> None:
    if blockchain_service.is_synced():
        return

    print('Waiting for the ethereum node to synchronize [Use ^C to exit].')

    for i in count():
        if i % 3 == 0:
            print('\r', end='')

        print('.', end='')
        sys.stdout.flush()

        gevent.sleep(sleep)

        if blockchain_service.is_synced():
            return

    # add a newline so that the next print will start have it's own line
    print('')


def wait_for_sync(
        blockchain_service: BlockChainService,
        url: str,
        tolerance: int,
        sleep: float,
) -> None:
    # print something since the actual test may take a few moments for the first
    # iteration
    print('Checking if the ethereum node is synchronized')

    try:
        wait_for_sync_etherscan(blockchain_service, url, tolerance, sleep)
    except (RequestException, ValueError, KeyError):
        print('Cannot use {}. Request failed'.format(url))
        print('Falling back to eth_sync api.')

        wait_for_sync_rpc_api(blockchain_service, sleep)
