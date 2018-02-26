# -*- coding: utf-8 -*-

"""Console script for pathfinder."""
import logging
import sys

import click

from pathfinder.blockchain import BlockchainMonitor
from pathfinder.no_ssl_patch import no_ssl_verification
from pathfinder.pathfinding_service import PathfindingService
from pathfinder.transport import MatrixTransport

log = logging.getLogger(__name__)


@click.command()
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
    monitoring_channel,
    matrix_homeserver,
    matrix_username,
    matrix_password
):
    """Console script for pathfinder."""

    # setup logging
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('urllib3.connectionpool').setLevel(logging.DEBUG)

    log.info("Starting Raiden Pathfinding Service")

    with no_ssl_verification():
        log.info('Starting Matrix Transport')
        transport = MatrixTransport(
            matrix_homeserver,
            matrix_username,
            matrix_password,
            monitoring_channel
        )

        log.info('Starting Blockchain Monitor')
        monitor = BlockchainMonitor()

        log.info('Starting Pathfinding Service')
        service = PathfindingService(transport, monitor)

        try:
            service.run()
        except (KeyboardInterrupt, SystemExit):
            print('Exiting...')
        finally:
            service.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
