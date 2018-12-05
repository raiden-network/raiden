"""Console script for pathfinder."""
from gevent import monkey  # isort:skip # noqa
monkey.patch_all()  # isort:skip # noqa

import logging
import sys

import click
from raiden_libs.blockchain import BlockchainListener
from raiden_contracts.contract_manager import ContractManager, contracts_precompiled_path
from web3 import HTTPProvider, Web3
from raiden_libs.no_ssl_patch import no_ssl_verification
from requests.exceptions import ConnectionError

from pathfinder.pathfinding_service import PathfindingService

log = logging.getLogger(__name__)
contract_manager = ContractManager(contracts_precompiled_path())


@click.command()
@click.option(
    '--eth-rpc',
    default='http://localhost:8545',
    type=str,
    help='Ethereum node RPC URI'
)
def main(
    eth_rpc,
):
    """Console script for pathfinder."""

    # setup logging
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('urllib3.connectionpool').setLevel(logging.DEBUG)

    log.info("Starting Raiden Pathfinding Service")

    try:
        log.info(f'Starting Web3 client for node at {eth_rpc}')
        web3 = Web3(HTTPProvider(eth_rpc))
    except ConnectionError:
        log.error(
            'Can not connect to the Ethereum client. Please check that it is running and that '
            'your settings are correct.'
        )
        sys.exit()

    with no_ssl_verification():
        service = None
        try:
            log.info('Starting TokenNetwork Listener...')
            token_network_listener = BlockchainListener(
                web3=web3,
                contract_manager=contract_manager,
                contract_name='TokenNetwork',
            )

            log.info('Starting TokenNetworkRegistry Listener...')
            token_network_registry_listener = BlockchainListener(
                web3=web3,
                contract_manager=contract_manager,
                contract_name='TokenNetworkRegistry',
            )

            log.info('Starting Pathfinding Service...')
            service = PathfindingService(
                contract_manager=contract_manager,
                token_network_listener=token_network_listener,
                token_network_registry_listener=token_network_registry_listener,
                chain_id=int(web3.net.version),
            )

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
