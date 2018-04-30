# -*- coding: utf-8 -*-

"""Console script for pathfinder."""
from gevent import monkey  # isort:skip # noqa
monkey.patch_all()  # isort:skip # noqa

import logging
import sys
from typing import List

import click
from raiden_libs.blockchain import BlockchainListener
from raiden_contracts.contract_manager import CONTRACT_MANAGER
from web3 import HTTPProvider, Web3
from hexbytes import HexBytes
from eth_utils import is_checksum_address
from raiden_libs.no_ssl_patch import no_ssl_verification
from raiden_libs.types import Address
from requests.exceptions import ConnectionError

from pathfinder.pathfinding_service import PathfindingService
from raiden_libs.transport import MatrixTransport

log = logging.getLogger(__name__)


def is_code_at_address(token_network_address: Address, web3: Web3) -> bool:
    code_at_address = web3.eth.getCode(token_network_address)
    return code_at_address != HexBytes('0x')


def check_supplied_token_network_addresses(
    token_network_addresses: List[str],
    web3: Web3
) -> List[Address]:
    result = []
    for address in token_network_addresses:
        if not is_checksum_address(address):
            log.error(f"Token Network address '{address}' is not a checksum address. Ignoring.")
            continue

        if not is_code_at_address(Address(address), web3):
            log.error(f"Token network at '{address}' has no code. Ignoring.")
            continue

        result.append(Address(address))

    return result


@click.command()
@click.option(
    '--eth-rpc',
    default='http://localhost:8545',
    type=str,
    help='Ethereum node RPC URI'
)
@click.option(
    '--monitoring-channel',
    default='#monitor_test:transport01.raiden.network',
    help='Location of the monitoring channel to connect to'
)
@click.option(
    '--matrix-homeserver',
    default='https://transport01.raiden.network',
    help='Matrix homeserver'
)
@click.option(
    '--matrix-username',
    default=None,
    required=True,
    help='Matrix username'
)
@click.option(
    '--matrix-password',
    default=None,
    required=True,
    help='Matrix password'
)
@click.argument(
    'token_network_addresses',
    nargs=-1
)
def main(
    eth_rpc,
    monitoring_channel,
    matrix_homeserver,
    matrix_username,
    matrix_password,
    token_network_addresses,
):
    """Console script for pathfinder."""

    # setup logging
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('urllib3.connectionpool').setLevel(logging.DEBUG)

    log.info("Starting Raiden Pathfinding Service")

    try:
        log.info(f'Starting Web3 client for node at {eth_rpc}')
        web3 = Web3(HTTPProvider(eth_rpc))

        token_network_addresses = check_supplied_token_network_addresses(
            token_network_addresses,
            web3
        )
        if token_network_addresses:
            log.info(f'Following {len(token_network_addresses)} network(s):')
        else:
            log.info('Following all networks.')
    except ConnectionError as error:
        log.error(
            'Can not connect to the Ethereum client. Please check that it is running and that '
            'your settings are correct.'
        )
        sys.exit()

    with no_ssl_verification():
        service = None
        try:
            log.info('Starting Matrix Transport...')
            transport = MatrixTransport(
                matrix_homeserver,
                matrix_username,
                matrix_password,
                monitoring_channel
            )

            log.info('Starting TokenNetwork Listener...')
            token_network_listener = BlockchainListener(
                web3,
                CONTRACT_MANAGER,
                'TokenNetwork',
            )

            log.info('Starting Pathfinding Service...')
            if token_network_addresses:
                service = PathfindingService(
                    CONTRACT_MANAGER,
                    transport,
                    token_network_listener,
                    follow_networks=token_network_addresses)
            else:
                log.info('Starting TokenNetworkRegistry Listener...')
                token_network_registry_listener = BlockchainListener(
                    web3,
                    CONTRACT_MANAGER,
                    'TokenNetworkRegistry',
                )

                service = PathfindingService(
                    CONTRACT_MANAGER,
                    transport,
                    token_network_listener,
                    token_network_registry_listener=token_network_registry_listener)

            service.run()
        except (KeyboardInterrupt, SystemExit):
            print('Exiting...')
        finally:
            if service:
                log.info('Stopping Pathfinding Service...')
                service.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
