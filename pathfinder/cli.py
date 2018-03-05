# -*- coding: utf-8 -*-

"""Console script for pathfinder."""

from gevent import monkey  # noqa
monkey.patch_all()  # noqa

import logging
import sys

import click
# from web3 import HTTPProvider, Web3

from pathfinder.no_ssl_patch import no_ssl_verification
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.transport import MatrixTransport


# from raiden_libs.blockchain import BlockchainListener


log = logging.getLogger(__name__)


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
def main(
    eth_rpc,
    monitoring_channel,
    matrix_homeserver,
    matrix_username,
    matrix_password
):
    """Console script for pathfinder."""

    # setup logging
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.DEBUG)

    log.info("Starting Raiden Pathfinding Service")

    with no_ssl_verification():
        try:
            log.info('Starting Matrix Transport...')
            transport = MatrixTransport(
                matrix_homeserver,
                matrix_username,
                matrix_password,
                monitoring_channel
            )

            log.info('Starting Web3 client...')
            # w3 = Web3(HTTPProvider(eth_rpc))

            log.info('Starting Blockchain Monitor...')
            # monitor = BlockchainListener(w3)

            log.info('Starting Pathfinding Service...')
            service = PathfindingService(transport)

            service.run()
        except (KeyboardInterrupt, SystemExit):
            print('Exiting...')
        finally:
            service.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
