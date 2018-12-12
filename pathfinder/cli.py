"""Console script for pathfinder."""
from gevent import monkey  # isort:skip # noqa
monkey.patch_all()  # isort:skip # noqa

import logging
import sys

import click
from eth_utils import is_checksum_address
from requests.exceptions import ConnectionError
from web3 import HTTPProvider, Web3

from pathfinder.api.rest import ServiceApi
from pathfinder.pathfinding_service import PathfindingService
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK_REGISTRY
from raiden_contracts.contract_manager import (
    ContractManager,
    contracts_precompiled_path,
    get_contracts_deployed,
)
from raiden_libs.no_ssl_patch import no_ssl_verification

log = logging.getLogger(__name__)
contract_manager = ContractManager(contracts_precompiled_path())

DEFAULT_REQUIRED_CONFIRMATIONS = 8  # ~2min with 15s blocks


@click.command()
@click.option(
    '--eth-rpc',
    default='http://localhost:8545',
    type=str,
    help='Ethereum node RPC URI',
)
@click.option(
    '--registry-address',
    type=str,
    help='Address of the token network registry',
)
@click.option(
    '--start-block',
    default=0,
    type=int,
    help='Block to start syncing at',
)
@click.option(
    '--confirmations',
    default=DEFAULT_REQUIRED_CONFIRMATIONS,
    type=int,
    help='Number of block confirmations to wait for',
)
def main(
    eth_rpc,
    registry_address,
    start_block,
    confirmations,
):
    """Console script for pathfinder."""

    # setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%m-%d %H:%M:%S',
    )

    logging.getLogger('web3').setLevel(logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)

    log.info("Starting Raiden Pathfinding Service")

    contracts_version = 'pre_limits'
    log.info(f'Using contracts version: {contracts_version}')

    try:
        log.info(f'Starting Web3 client for node at {eth_rpc}')
        web3 = Web3(HTTPProvider(eth_rpc))
    except ConnectionError:
        log.error(
            'Can not connect to the Ethereum client. Please check that it is running and that '
            'your settings are correct.',
        )
        sys.exit()

    with no_ssl_verification():
        valid_params_given = is_checksum_address(registry_address) and start_block >= 0
        if not valid_params_given:
            try:
                contract_data = get_contracts_deployed(int(web3.net.version), contracts_version)
                token_network_registry_info = contract_data['contracts'][CONTRACT_TOKEN_NETWORK_REGISTRY]  # noqa
                registry_address = token_network_registry_info['address']
                start_block = max(0, token_network_registry_info['block_number'] - 100)
            except ValueError:
                log.error(
                    'Provided registry address or start block are not valid and '
                    'no deployed contracts were found',
                )
                sys.exit(1)

        service = None
        try:
            log.info('Starting Pathfinding Service...')
            service = PathfindingService(
                web3=web3,
                contract_manager=contract_manager,
                registry_address=registry_address,
                sync_start_block=start_block,
                required_confirmations=confirmations,
            )

            api = ServiceApi(service)
            api.run()

            service.run()
        except (KeyboardInterrupt, SystemExit):
            print('Exiting...')
        finally:
            if service:
                log.info('Stopping Pathfinding Service...')
                service.stop()

    return 0


if __name__ == "__main__":
    main(auto_envvar_prefix='PFS')  # pragma: no cover
