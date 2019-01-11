"""Console script for pathfinding_service."""
from gevent import monkey  # isort:skip # noqa
monkey.patch_all()  # isort:skip # noqa

import json
import logging
import logging.config
import sys
from typing import TextIO

import click
from eth_utils import is_checksum_address
from requests.exceptions import ConnectionError
from web3 import HTTPProvider, Web3

from pathfinding_service import PathfindingService
from pathfinding_service.api.rest import ServiceApi
from pathfinding_service.config import DEFAULT_API_HOST
from pathfinding_service.middleware import http_retry_with_backoff_middleware
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK_REGISTRY
from raiden_contracts.contract_manager import (
    ContractManager,
    contracts_precompiled_path,
    get_contracts_deployed,
)
from raiden_libs.types import Address

log = logging.getLogger(__name__)
contract_manager = ContractManager(contracts_precompiled_path())

DEFAULT_REQUIRED_CONFIRMATIONS = 8  # ~2min with 15s blocks


def validate_address(ctx, param, value):
    if value is None:
        # None as default value allowed
        return None
    if not is_checksum_address(value):
        raise click.BadParameter('not an EIP-55 checksummed address')
    return value


def get_default_registry_and_start_block(
    net_version: int,
    contracts_version: str,
):
    try:
        contract_data = get_contracts_deployed(net_version, contracts_version)
        token_network_registry_info = contract_data['contracts'][CONTRACT_TOKEN_NETWORK_REGISTRY]
        registry_address = token_network_registry_info['address']
        start_block = max(0, token_network_registry_info['block_number'] - 100)
        return registry_address, start_block
    except ValueError:
        log.error('No deployed contracts were found at the default registry')
        sys.exit(1)


def setup_logging(log_level: str, log_config: TextIO):
    """ Set log level and (optionally) detailed JSON logging config """
    level = getattr(logging, log_level)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%m-%d %H:%M:%S',
    )

    if log_config:
        config = json.load(log_config)
        logging.config.dictConfig(config)


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
    callback=validate_address,
)
@click.option(
    '--start-block',
    default=0,
    type=click.IntRange(min=0),
    help='Block to start syncing at',
)
@click.option(
    '--confirmations',
    default=DEFAULT_REQUIRED_CONFIRMATIONS,
    type=click.IntRange(min=0),
    help='Number of block confirmations to wait for',
)
@click.option(
    '--host',
    default=DEFAULT_API_HOST,
    type=str,
    help='The host to use for serving the REST API',
)
@click.option(
    '--log-level',
    default='INFO',
    type=click.Choice(['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']),
    help='Print log messages of this level and more important ones',
)
@click.option(
    '--log-config',
    type=click.File('r'),
    help='Use the given JSON file for logging configuration',
)
def main(
    eth_rpc: str,
    registry_address: Address,
    start_block: int,
    confirmations: int,
    host: str,
    log_level: str,
    log_config: TextIO,
):
    """Console script for pathfinding_service.

    Logging can be quickly set by specifying a global log level or in a
    detailed way by using a log configuration file. See
    https://docs.python.org/3.7/library/logging.config.html#logging-config-dictschema
    for a detailed description of the format.
    """

    setup_logging(log_level, log_config)

    log.info("Starting Raiden Pathfinding Service")

    contracts_version = 'pre_limits'
    log.info(f'Using contracts version: {contracts_version}')

    try:
        log.info(f'Starting Web3 client for node at {eth_rpc}')
        provider = HTTPProvider(eth_rpc)
        web3 = Web3(provider)
        net_version = int(web3.net.version)  # Will throw ConnectionError on bad Ethereum client
    except ConnectionError:
        log.error(
            'Can not connect to the Ethereum client. Please check that it is running and that '
            'your settings are correct.',
        )
        sys.exit(1)

    # give web3 some time between retries before failing
    provider.middlewares.replace(
        'http_retry_request',
        http_retry_with_backoff_middleware,
    )

    if registry_address is None:
        registry_address, start_block = get_default_registry_and_start_block(
                net_version,
                contracts_version,
        )

    service = None
    api = None
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
        api.run(host=host)

        service.run()
    except (KeyboardInterrupt, SystemExit):
        print('Exiting...')
    finally:
        log.info('Stopping Pathfinding Service...')
        if api:
            api.stop()
        if service:
            service.stop()

    return 0


if __name__ == "__main__":
    main(auto_envvar_prefix='PFS')  # pragma: no cover
